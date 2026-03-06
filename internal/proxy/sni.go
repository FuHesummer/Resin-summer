package proxy

import "net"

// extractSNI attempts to parse a TLS ClientHello from data and return the
// Server Name Indication (SNI) extension value.
//
// Returns ("", false) if the data is not a valid TLS ClientHello or does not
// contain an SNI extension.
//
// This is a minimal, allocation-light parser that only reads enough of the
// record to extract the SNI hostname. It does not validate the full
// ClientHello structure beyond what is necessary to locate the SNI field.
func extractSNI(data []byte) (serverName string, ok bool) {
	// TLS record header: ContentType(1) + Version(2) + Length(2) = 5 bytes
	if len(data) < 5 {
		return "", false
	}
	// ContentType must be Handshake (0x16).
	if data[0] != 0x16 {
		return "", false
	}
	// Record payload length.
	recordLen := int(data[3])<<8 | int(data[4])
	payload := data[5:]
	if len(payload) < recordLen {
		// Incomplete record — use what we have; SNI is near the front.
		payload = payload[:len(payload)]
	} else {
		payload = payload[:recordLen]
	}

	// Handshake header: HandshakeType(1) + Length(3) = 4 bytes
	if len(payload) < 4 {
		return "", false
	}
	// HandshakeType must be ClientHello (0x01).
	if payload[0] != 0x01 {
		return "", false
	}
	// Skip handshake header.
	payload = payload[4:]

	// ClientHello body:
	// Version(2) + Random(32) = 34 bytes
	if len(payload) < 34 {
		return "", false
	}
	payload = payload[34:]

	// Session ID (variable length, 1-byte length prefix).
	if len(payload) < 1 {
		return "", false
	}
	sessIDLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < sessIDLen {
		return "", false
	}
	payload = payload[sessIDLen:]

	// Cipher Suites (2-byte length prefix).
	if len(payload) < 2 {
		return "", false
	}
	csLen := int(payload[0])<<8 | int(payload[1])
	payload = payload[2:]
	if len(payload) < csLen {
		return "", false
	}
	payload = payload[csLen:]

	// Compression Methods (1-byte length prefix).
	if len(payload) < 1 {
		return "", false
	}
	compLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < compLen {
		return "", false
	}
	payload = payload[compLen:]

	// Extensions (2-byte length prefix).
	if len(payload) < 2 {
		return "", false
	}
	extLen := int(payload[0])<<8 | int(payload[1])
	payload = payload[2:]
	if len(payload) < extLen {
		payload = payload[:len(payload)]
	} else {
		payload = payload[:extLen]
	}

	// Walk extensions looking for SNI (type 0x0000).
	for len(payload) >= 4 {
		extType := int(payload[0])<<8 | int(payload[1])
		extDataLen := int(payload[2])<<8 | int(payload[3])
		payload = payload[4:]
		if len(payload) < extDataLen {
			return "", false
		}
		if extType == 0x0000 { // server_name
			return parseSNIExtension(payload[:extDataLen])
		}
		payload = payload[extDataLen:]
	}

	return "", false
}

// parseSNIExtension parses the SNI extension data and returns the first
// host_name entry.
func parseSNIExtension(data []byte) (string, bool) {
	// ServerNameList length (2 bytes).
	if len(data) < 2 {
		return "", false
	}
	listLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < listLen {
		data = data[:len(data)]
	} else {
		data = data[:listLen]
	}

	// Walk ServerName entries.
	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(data[1])<<8 | int(data[2])
		data = data[3:]
		if len(data) < nameLen {
			return "", false
		}
		if nameType == 0x00 { // host_name
			name := string(data[:nameLen])
			// Sanity check: must look like a domain, not an IP.
			if net.ParseIP(name) != nil {
				return "", false
			}
			if name == "" {
				return "", false
			}
			return name, true
		}
		data = data[nameLen:]
	}

	return "", false
}
