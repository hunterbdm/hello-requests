package mimic

import (
	utls "github.com/hunterbdm/hello-requests/utls"
	"strings"
)

const (
	H2SettingHeaderTableSize       = 0x1
	H2SettingEnablePush            = 0x2
	H2SettingMaxConcurrentStreams  = 0x3
	H2SettingInitialWindowSize     = 0x4
	H2SettingMaxFrameSize          = 0x5
	H2SettingMaxHeaderListSize     = 0x6
)

var (
	// Chrome h2 fingerprint: 1:65536;3:1000;4:6291456;6:262144|15663105||m,a,s,p
	// 8a32ff5cb625ed4ae2d092e76beb6d99
	// Chrome tls fingerprint: 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0
	// b32309a26951912be7dba376398abc3b
	chromeMimic = Settings{
		H2HeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		H2Settings: []H2Setting{
			{ID: H2SettingHeaderTableSize, Val: 65536},
			{ID: H2SettingMaxConcurrentStreams, Val: 1000},
			{ID: H2SettingInitialWindowSize, Val: 6291456},
			{ID: H2SettingMaxHeaderListSize, Val: 262144},
		},
		H2StreamFlow: 15663105,
		ClientHello: func() *utls.ClientHelloSpec {
			return &utls.ClientHelloSpec{
				CipherSuites: []uint16{
					utls.GREASE_PLACEHOLDER,
					utls.TLS_AES_128_GCM_SHA256,
					utls.TLS_AES_256_GCM_SHA384,
					utls.TLS_CHACHA20_POLY1305_SHA256,
					utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					utls.TLS_RSA_WITH_AES_128_CBC_SHA,
					utls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{0x00},
				Extensions: []utls.TLSExtension{
					&utls.UtlsGREASEExtension{},
					&utls.SNIExtension{},
					&utls.UtlsExtendedMasterSecretExtension{},
					&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
					&utls.SupportedCurvesExtension{
						Curves: []utls.CurveID{
							utls.CurveID(utls.GREASE_PLACEHOLDER),
							utls.X25519,
							utls.CurveP256,
							utls.CurveP384,
						}},
					&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
					&utls.SessionTicketExtension{},
					&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&utls.StatusRequestExtension{},
					&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
						utls.ECDSAWithP256AndSHA256,
						utls.PSSWithSHA256,
						utls.PKCS1WithSHA256,
						utls.ECDSAWithP384AndSHA384,
						utls.PSSWithSHA384,
						utls.PKCS1WithSHA384,
						utls.PSSWithSHA512,
						utls.PKCS1WithSHA512,
						//utls.PKCS1WithSHA1,
					}},
					&utls.SCTExtension{},
					&utls.KeyShareExtension{
						KeyShares: []utls.KeyShare{
							{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
							{Group: utls.X25519},
						}},
						&utls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							utls.PskModeDHE,
						}},
					&utls.SupportedVersionsExtension{
						Versions: []uint16{
							utls.GREASE_PLACEHOLDER,
							utls.VersionTLS13,
							utls.VersionTLS12,
							utls.VersionTLS11,
							utls.VersionTLS10,
						}},
					&utls.CompressCertificateExtension{
						Algorithms: []utls.CertCompressionAlgo{
							utls.CertCompressionBrotli,
						}},
					&utls.UtlsGREASEExtension{},
					&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
				},
				TLSVersMax: utls.VersionTLS13,
				TLSVersMin: utls.VersionTLS10,
			}
		},
	}

	// Firefox h2 fingerprint: 1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s
	// 3d9132023bf26a71d40fe766e5c24c9d
	// Firefox tls fingerprint: 771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25,0
	// f2a9f94284e5d331627ccacf0511219b
	firefoxMimic = Settings{
		H2HeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		H2Settings: []H2Setting{
			{ID: H2SettingHeaderTableSize, Val: 65536},
			{ID: H2SettingInitialWindowSize, Val: 131072},
			{ID: H2SettingMaxFrameSize, Val: 16384},
		},
		H2StreamFlow: 12517377,
		H2PriorityFrames: []H2PriorityFrame{
			// 3:0:0:201
			{StreamID: 3, Exclusive: false, StreamDep: 0, Weight: 201},
			// 5:0:0:101
			{StreamID: 5, Exclusive: false, StreamDep: 0, Weight: 101},
			// 7:0:0:1
			{StreamID: 7, Exclusive: false, StreamDep: 0, Weight: 1},
			// 9:0:7:1
			{StreamID: 9, Exclusive: false, StreamDep: 7, Weight: 1},
			// 11:0:3:1
			{StreamID: 11, Exclusive: false, StreamDep: 3, Weight: 1},
			// 13:0:0:241
			{StreamID: 13, Exclusive: false, StreamDep: 0, Weight: 241},
		},

		ClientHello: func() *utls.ClientHelloSpec {
			return &utls.ClientHelloSpec{
				CipherSuites: []uint16{
					utls.TLS_AES_128_GCM_SHA256,
					utls.TLS_CHACHA20_POLY1305_SHA256,
					utls.TLS_AES_256_GCM_SHA384,
					utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					utls.TLS_RSA_WITH_AES_128_CBC_SHA,
					utls.TLS_RSA_WITH_AES_256_CBC_SHA,
					utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				},
				CompressionMethods: []byte{0x00},
				Extensions: []utls.TLSExtension{
					&utls.SNIExtension{},
					&utls.UtlsExtendedMasterSecretExtension{},
					&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
					&utls.SupportedCurvesExtension{
						Curves: []utls.CurveID{
							utls.X25519,
							utls.CurveP256,
							utls.CurveP384,
							utls.CurveP521,
							utls.CurveID(256),
							utls.CurveID(257),
						}},
					&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
					&utls.SessionTicketExtension{},
					&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&utls.StatusRequestExtension{},
					&utls.KeyShareExtension{
						KeyShares: []utls.KeyShare{
							{Group: utls.X25519},
							{Group: utls.CurveP256},
						}},
					&utls.SupportedVersionsExtension{
						Versions: []uint16{
							utls.VersionTLS13,
							utls.VersionTLS12,
						}},
					&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
						utls.ECDSAWithP256AndSHA256,
						utls.ECDSAWithP384AndSHA384,
						utls.ECDSAWithP521AndSHA512,
						utls.PSSWithSHA256,
						utls.PSSWithSHA384,
						utls.PSSWithSHA512,
						utls.PKCS1WithSHA256,
						utls.PKCS1WithSHA384,
						utls.PKCS1WithSHA512,
						utls.ECDSAWithSHA1,
						utls.PKCS1WithSHA1,
					}},
					&utls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							utls.PskModeDHE,
						}},
					&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
				},
				TLSVersMax: utls.VersionTLS13,
				TLSVersMin: utls.VersionTLS10,
			}
		},
	}

	mimicSettingsMap = map[string]Settings{
		"chrome": chromeMimic,
		"chrome83": chromeMimic,
		"firefox": firefoxMimic,
	}
)

type H2Setting struct {
	ID uint16
	Val uint32
}

type H2PriorityFrame struct {
	StreamID uint32
	Exclusive bool
	StreamDep uint32
	Weight uint8
}

type Settings struct {
	H2HeaderOrder []string
	H2Settings []H2Setting
	H2StreamFlow uint32
	H2PriorityFrames []H2PriorityFrame

	ClientHello func() *utls.ClientHelloSpec
}

func GetMimicSettings(browser string) *Settings {
	browser = strings.ToLower(browser)

	if data, ok := mimicSettingsMap[browser]; ok {
		return &data
	}

	return nil
}

func SetMimicSettings(browser string, settings Settings) {
	browser = strings.ToLower(browser)

	mimicSettingsMap[browser] = settings
}