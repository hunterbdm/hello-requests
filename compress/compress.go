package compress

import (
	"bytes"
	"compress/gzip"
	"github.com/dsnet/compress/brotli"
	"io/ioutil"
)

func Decompress(data []byte, encoding string) string {
	if encoding == "gzip" {
		if newData, err := decompressGzip(data); err == nil {
			data = *newData
		}
	} else if encoding == "br" {
		if newData, err := decompressBrotli(data); err == nil {
			data = *newData
		}
	}
	// TODO add others later

	return string(data)
}

func decompressGzip(data []byte) (*[]byte, error) {
	if gr, err := gzip.NewReader(bytes.NewBuffer(data)); err != nil {
		return nil, err
	} else {
		defer gr.Close()
		data, _ = ioutil.ReadAll(gr)
		return &data, nil
	}
}

func decompressBrotli(data []byte) (*[]byte, error) {
	if gr, err := brotli.NewReader(bytes.NewBuffer(data), nil); err != nil {
		return nil, err
	} else {
		defer gr.Close()
		data, _ = ioutil.ReadAll(gr)
		return &data, nil
	}
}