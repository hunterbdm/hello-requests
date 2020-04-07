package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"hello-requests/connector/aes"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	request "hello-requests"

	"github.com/gorilla/websocket"
)

var (
	upgrader = websocket.Upgrader{}

	jobChan = make(chan job)
	// Sets the amount of active requests at once
	workerAmount = 300

	// Cipher Key used for the aes-256 encryption on websocket
	// Must be 32 characters
	cipherKey = "02b7217009ac9ac0df2ee35253c16269"
	//cipherKey = ""

	// Dev key used to bypass security features
	// Set to empty string to disable it
	devKey = "G2B898nzyfSqd2Ub7BYPMLPcMTDbEsUM"

	// List of valid names for executable
	// No need to put the file type (.exe)
	// leave empty for no check
	validFileNames = []string{
		"wsrs",
		"wsr",
		"main",
	}
	// List of valid file names where the executeable can be run from
	validPaths = []string{
		"/dashe/",
		"\\dashe\\",
		"/hastey/",
		"\\hastey\\",
		"\\go-build",
	}
)

type job struct {
	message   []byte
	c         *websocket.Conn
	connMutex *sync.Mutex
}

func worker(jobChan <-chan job) {
	for job := range jobChan {
		handleRequest(job)
	}
}

func handleRequest(job job) {
	message := string(job.message)
	// Decrypt payload if needed
	if len(cipherKey) > 0 {
		message, _ = aes.Decrypt(message, cipherKey)
	}

	var opts request.Options
	err := json.Unmarshal([]byte(message), &opts)
	if err != nil {
		return
	}

	// Do ID check here

	resp, err := request.Do(opts)
	if err != nil {
		fmt.Println(err)
	}

	payload, _ := json.Marshal(resp)
	payloadStr := string(payload)
	if len(cipherKey) > 0 {
		payloadStr, _ = aes.Encrypt(payloadStr, cipherKey)
	}

	job.connMutex.Lock()
	job.c.WriteMessage(1, []byte(payloadStr))
	job.connMutex.Unlock()
}

func securityChecks() bool {
	if len(devKey) > 0 && os.Getenv("HR_DEV_KEY") == devKey {
		return true
	}

	// Statuses for each security check done
	checks := map[string]bool{
		"path":     false,
		"filename": false,
	}

	path := os.Args[0]
	filename := filepath.Base(os.Args[0])
	filename = strings.Split(filename, ".")[0] // Remove file extension

	// Checking path
	for _, p := range validPaths {
		if strings.Contains(path, p) {
			checks["path"] = true
			break
		}
	}

	// Checking file name
	for _, fn := range validFileNames {
		if filename == fn {
			checks["filename"] = true
			break
		}
	}

	for check, pass := range checks {
		if !pass {
			fmt.Println("Failed " + check + " check")
			return false
		}
	}

	return true
}

func webSocket(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil) // make it a websocket
	if err != nil {
		log.Print("Failed websocket upgrade:", err)
		return
	}
	defer c.Close()

	// used to ensure we dont write to the connection more than once at any given time
	connMutex := sync.Mutex{}

	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			// Failed reading message
			break
		}

		jobChan <- job{
			message:   message,
			c:         c,
			connMutex: &connMutex,
		}
	}
}

func main() {
	if !securityChecks() {
		os.Exit(1)
		return
	}

	// Configure local websocket server address
	var addr *string
	if len(os.Args) == 2 {
		addr = flag.String("addr", "localhost:"+os.Args[1], "http service address")
	} else {
		addr = flag.String("addr", "localhost:5183", "http service address")
	}

	// Start request workers
	for i := 0; i < 300; i++ {
		go worker(jobChan)
	}

	// Start listening on webserver
	http.HandleFunc("/req", webSocket)
	http.ListenAndServe(*addr, nil)
	//http.ListenAndServe(*addr, nil)
	return
}
