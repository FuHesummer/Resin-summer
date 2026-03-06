package proxy

import (
	"testing"
)

func TestExtractSNI(t *testing.T) {
	// Real TLS 1.2 ClientHello for www.google.com (captured and trimmed).
	// This is a minimal valid ClientHello with SNI extension.
	hello := buildTestClientHello("www.google.com")

	sni, ok := extractSNI(hello)
	if !ok {
		t.Fatal("expected SNI extraction to succeed")
	}
	if sni != "www.google.com" {
		t.Fatalf("expected www.google.com, got %q", sni)
	}
}

func TestExtractSNI_NoSNI(t *testing.T) {
	// A ClientHello with no extensions.
	hello := buildTestClientHelloNoSNI()
	_, ok := extractSNI(hello)
	if ok {
		t.Fatal("expected SNI extraction to fail for hello without SNI")
	}
}

func TestExtractSNI_NotTLS(t *testing.T) {
	_, ok := extractSNI([]byte("GET / HTTP/1.1\r\n"))
	if ok {
		t.Fatal("expected SNI extraction to fail for non-TLS data")
	}
}

func TestExtractSNI_TooShort(t *testing.T) {
	_, ok := extractSNI([]byte{0x16, 0x03})
	if ok {
		t.Fatal("expected SNI extraction to fail for short data")
	}
}

func TestExtractSNI_IPAddress(t *testing.T) {
	// ClientHello where the SNI field contains an IP address — should return false.
	hello := buildTestClientHello("1.2.3.4")
	_, ok := extractSNI(hello)
	if ok {
		t.Fatal("expected SNI extraction to reject IP address in SNI")
	}
}

func TestExtractSNI_RealWorldHello(t *testing.T) {
	// Test with a different domain to ensure the builder works for various names.
	hello := buildTestClientHello("api.example.com")

	sni, ok := extractSNI(hello)
	if !ok {
		t.Fatal("expected SNI extraction to succeed")
	}
	if sni != "api.example.com" {
		t.Fatalf("expected api.example.com, got %q", sni)
	}
}

// buildTestClientHello constructs a minimal TLS ClientHello with the given SNI.
func buildTestClientHello(serverName string) []byte {
	sniBytes := []byte(serverName)
	// SNI extension data:
	//   ServerNameList length (2) + NameType (1) + NameLen (2) + Name
	sniExtData := make([]byte, 0, 2+1+2+len(sniBytes))
	sniListLen := 1 + 2 + len(sniBytes)
	sniExtData = append(sniExtData, byte(sniListLen>>8), byte(sniListLen))
	sniExtData = append(sniExtData, 0x00) // host_name type
	sniExtData = append(sniExtData, byte(len(sniBytes)>>8), byte(len(sniBytes)))
	sniExtData = append(sniExtData, sniBytes...)

	// Extension header: type (2) + length (2) + data
	ext := make([]byte, 0, 4+len(sniExtData))
	ext = append(ext, 0x00, 0x00) // SNI extension type
	ext = append(ext, byte(len(sniExtData)>>8), byte(len(sniExtData)))
	ext = append(ext, sniExtData...)

	// Extensions block: length (2) + extensions
	extsBlock := make([]byte, 0, 2+len(ext))
	extsBlock = append(extsBlock, byte(len(ext)>>8), byte(len(ext)))
	extsBlock = append(extsBlock, ext...)

	// ClientHello body:
	//   Version (2) + Random (32) + SessionIDLen (1) + CipherSuitesLen (2) +
	//   CipherSuite (2) + CompMethodsLen (1) + CompMethod (1) + Extensions
	body := make([]byte, 0, 2+32+1+2+2+1+1+len(extsBlock))
	body = append(body, 0x03, 0x03) // TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)       // session ID length = 0
	body = append(body, 0x00, 0x02) // cipher suites length = 2
	body = append(body, 0x00, 0xff) // a cipher suite
	body = append(body, 0x01, 0x00) // compression methods: 1 method, null
	body = append(body, extsBlock...)

	// Handshake header: type (1) + length (3)
	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01) // ClientHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// TLS record header: ContentType (1) + Version (2) + Length (2)
	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16)       // Handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 record version (standard)
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

// buildTestClientHelloNoSNI constructs a minimal TLS ClientHello without extensions.
func buildTestClientHelloNoSNI() []byte {
	// ClientHello body without extensions.
	body := make([]byte, 0, 2+32+1+2+2+1+1)
	body = append(body, 0x03, 0x03) // TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)       // session ID length = 0
	body = append(body, 0x00, 0x02) // cipher suites length = 2
	body = append(body, 0x00, 0xff) // a cipher suite
	body = append(body, 0x01, 0x00) // compression methods: 1 method, null

	// Handshake header.
	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01)
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// TLS record header.
	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16, 0x03, 0x01)
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}
