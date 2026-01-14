package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	listenAddr = ":8443"
	outDir     = "captures"
	maxBytes   = 256 * 1024
)

// -------------------- Capture: TLS records until full ClientHello --------------------

func readClientHelloTLSRecords(conn net.Conn, maxBytes int) (capturedRecords []byte, clientHelloHandshake []byte, err error) {
	var handshakePayload bytes.Buffer
	expectedHandshakeLen := -1

	readFull := func(n int) ([]byte, error) {
		b := make([]byte, n)
		_, e := io.ReadFull(conn, b)
		return b, e
	}

	total := 0
	for {
		if total > maxBytes {
			return capturedRecords, clientHelloHandshake, fmt.Errorf("exceeded maxBytes=%d waiting for ClientHello", maxBytes)
		}

		// TLS record header: ContentType(1) + Version(2) + Length(2)
		hdr, e := readFull(5)
		if e != nil {
			return capturedRecords, clientHelloHandshake, e
		}
		total += 5

		recType := hdr[0]
		recLen := int(hdr[3])<<8 | int(hdr[4])

		body, e := readFull(recLen)
		if e != nil {
			return capturedRecords, clientHelloHandshake, e
		}
		total += recLen

		capturedRecords = append(capturedRecords, hdr...)
		capturedRecords = append(capturedRecords, body...)

		// 22 = Handshake record
		if recType != 22 {
			continue
		}

		handshakePayload.Write(body)
		hb := handshakePayload.Bytes()

		// Handshake header: msg_type(1) + length(3)
		if len(hb) >= 4 && expectedHandshakeLen < 0 {
			msgType := hb[0]
			msgLen := int(hb[1])<<16 | int(hb[2])<<8 | int(hb[3])
			if msgType != 1 {
				return capturedRecords, clientHelloHandshake, fmt.Errorf("first handshake msg is not ClientHello (type=%d)", msgType)
			}
			expectedHandshakeLen = 4 + msgLen
		}

		if expectedHandshakeLen > 0 && len(hb) >= expectedHandshakeLen {
			clientHelloHandshake = hb[:expectedHandshakeLen]
			return capturedRecords, clientHelloHandshake, nil
		}
	}
}

// -------------------- JA4 helpers --------------------

func isGREASE(v uint16) bool {
	// GREASE values are 0x?a?a (0x0a0a, 0x1a1a, ...)
	return (v&0x0f0f) == 0x0a0a
}

func tlsVersionToJA4(v uint16) string {
	switch v {
	case 0x0304:
		return "13" // TLS 1.3
	case 0x0303:
		return "12" // TLS 1.2
	case 0x0302:
		return "11" // TLS 1.1
	case 0x0301:
		return "10" // TLS 1.0
	default:
		return "00"
	}
}

func sha256_12hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	h := hex.EncodeToString(sum[:])
	return h[:12]
}

func joinHex4Comma(list []uint16) string {
	parts := make([]string, 0, len(list))
	for _, v := range list {
		parts = append(parts, fmt.Sprintf("%04x", v))
	}
	return strings.Join(parts, ",")
}

func sortedNoGrease(list []uint16) []uint16 {
	out := make([]uint16, 0, len(list))
	for _, v := range list {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// JA4_a ALPN marker per common implementations: first and last character
// of the first ALPN value. If none => "00". If length 1 => doubled.
func alpnMarkerFirstLast(token []byte) string {
	if len(token) == 0 {
		return "00"
	}
	if len(token) == 1 {
		return string([]byte{token[0], token[0]})
	}
	return string([]byte{token[0], token[len(token)-1]})
}

// -------------------- Parse ClientHello + compute JA4 --------------------
//
// Returns:
// - ja4a: e.g. t13d1516h2
// - ja4 : e.g. t13d1516h2_8daaf6152771_02713d6af862
//
// Input ch must be the *handshake message* bytes:
//   HandshakeType(1)=1 + Length(3) + ClientHelloBody...
//
func computeJA4FromClientHelloHandshake(ch []byte) (ja4a string, ja4 string, err error) {
	if len(ch) < 4 {
		return "", "", fmt.Errorf("clienthello too short")
	}
	if ch[0] != 1 {
		return "", "", fmt.Errorf("not a ClientHello (type=%d)", ch[0])
	}

	r := bytes.NewReader(ch)

	// Handshake header
	var hsType uint8
	if err := binary.Read(r, binary.BigEndian, &hsType); err != nil {
		return "", "", err
	}
	var hsLen3 [3]byte
	if _, err := io.ReadFull(r, hsLen3[:]); err != nil {
		return "", "", err
	}

	// ClientHello body:
	// legacy_version (2)
	var legacyVersion uint16
	if err := binary.Read(r, binary.BigEndian, &legacyVersion); err != nil {
		return "", "", err
	}

	// random (32)
	if _, err := r.Seek(32, io.SeekCurrent); err != nil {
		return "", "", err
	}

	// session_id
	var sidLen uint8
	if err := binary.Read(r, binary.BigEndian, &sidLen); err != nil {
		return "", "", err
	}
	if _, err := r.Seek(int64(sidLen), io.SeekCurrent); err != nil {
		return "", "", err
	}

	// cipher_suites
	var csLen uint16
	if err := binary.Read(r, binary.BigEndian, &csLen); err != nil {
		return "", "", err
	}
	if csLen%2 != 0 {
		return "", "", fmt.Errorf("cipher_suites length not even")
	}

	cipherSuites := make([]uint16, 0, int(csLen)/2)
	cipherCountNoGrease := 0
	for i := 0; i < int(csLen)/2; i++ {
		var cs uint16
		if err := binary.Read(r, binary.BigEndian, &cs); err != nil {
			return "", "", err
		}
		cipherSuites = append(cipherSuites, cs)
		if !isGREASE(cs) {
			cipherCountNoGrease++
		}
	}

	// compression_methods
	var compLen uint8
	if err := binary.Read(r, binary.BigEndian, &compLen); err != nil {
		return "", "", err
	}
	if _, err := r.Seek(int64(compLen), io.SeekCurrent); err != nil {
		return "", "", err
	}

	// extensions length (2) then extensions
	var extLen uint16
	if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
		// extremely rare for real clients
		ver := tlsVersionToJA4(legacyVersion)
		ja4a = fmt.Sprintf("t%s%s%02d%02d%s", ver, "i", cipherCountNoGrease, 0, "00")
		ja4b := sha256_12hex(joinHex4Comma(sortedNoGrease(cipherSuites)))
		ja4c := sha256_12hex("")
		ja4 = fmt.Sprintf("%s_%s_%s", ja4a, ja4b, ja4c)
		return ja4a, ja4, nil
	}

	extBytes := make([]byte, extLen)
	if _, err := io.ReadFull(r, extBytes); err != nil {
		return "", "", err
	}

	er := bytes.NewReader(extBytes)

	extIDs := make([]uint16, 0, 32)
	extCountNoGrease := 0

	hasSNI := false
	alpnMarker := "00"

	highestTLS := legacyVersion
	hasSupportedVersions := false

	// signature_algorithms (0x000d) in the order observed
	sigAlgs := make([]uint16, 0, 16)

	for er.Len() > 0 {
		if er.Len() < 4 {
			break
		}
		var extType, extSize uint16
		if err := binary.Read(er, binary.BigEndian, &extType); err != nil {
			return "", "", err
		}
		if err := binary.Read(er, binary.BigEndian, &extSize); err != nil {
			return "", "", err
		}
		if int(extSize) > er.Len() {
			break
		}
		data := make([]byte, extSize)
		if _, err := io.ReadFull(er, data); err != nil {
			return "", "", err
		}

		extIDs = append(extIDs, extType)
		if !isGREASE(extType) {
			extCountNoGrease++
		}

		switch extType {
		case 0x0000: // SNI
			hasSNI = true

		case 0x002b: // supported_versions
			// data: len(1) + versions(uint16)...
			if len(data) >= 1 {
				listLen := int(data[0])
				// must be pairs of uint16
				if 1+listLen <= len(data) && (listLen%2 == 0) {
					hasSupportedVersions = true
					for i := 1; i+1 < 1+listLen; i += 2 {
						v := binary.BigEndian.Uint16(data[i : i+2])
						if !isGREASE(v) && v > highestTLS {
							highestTLS = v
						}
					}
				}
			}

		case 0x0010: // ALPN
			// data: ProtocolNameList length(2), then repeated: name_len(1) + name bytes
			if len(data) >= 2 {
				listLen := int(binary.BigEndian.Uint16(data[0:2]))
				if 2+listLen <= len(data) {
					p := data[2 : 2+listLen]
					if len(p) >= 1 {
						nameLen := int(p[0])
						if nameLen > 0 && 1+nameLen <= len(p) {
							name := p[1 : 1+nameLen] // first ALPN token
							alpnMarker = alpnMarkerFirstLast(name)
						}
					}
				}
			}

		case 0x000d: // signature_algorithms
			// data: list_length(2) + sequence of uint16
			if len(data) >= 2 {
				ll := int(binary.BigEndian.Uint16(data[0:2]))
				if 2+ll <= len(data) && (ll%2 == 0) {
					p := data[2 : 2+ll]
					for i := 0; i+1 < len(p); i += 2 {
						sa := binary.BigEndian.Uint16(p[i : i+2])
						sigAlgs = append(sigAlgs, sa)
					}
				}
			}
		}
	}

	// JA4_a TLS version: use supported_versions (if present), else legacy
	ver := legacyVersion
	if hasSupportedVersions {
		ver = highestTLS
	}
	ja4ver := tlsVersionToJA4(ver)

	sniFlag := "i"
	if hasSNI {
		sniFlag = "d"
	}

	ja4a = fmt.Sprintf("t%s%s%02d%02d%s", ja4ver, sniFlag, cipherCountNoGrease, extCountNoGrease, alpnMarker)

	// JA4_b: hash of sorted cipher suites (no GREASE)
	ja4br := joinHex4Comma(sortedNoGrease(cipherSuites))
	ja4b := sha256_12hex(ja4br)

	// JA4_c raw: sorted ext list (no GREASE, excluding SNI+ALPN) + "_" + sigalgs (if present)
	extForC := make([]uint16, 0, len(extIDs))
	for _, e := range extIDs {
		if isGREASE(e) {
			continue
		}
		// Exclude SNI (0000) and ALPN (0010) from the hashed extension list
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		extForC = append(extForC, e)
	}
	sort.Slice(extForC, func(i, j int) bool { return extForC[i] < extForC[j] })

	ja4cr := joinHex4Comma(extForC)
	if len(sigAlgs) > 0 {
		ja4cr = ja4cr + "_" + joinHex4Comma(sigAlgs) // keep observed order
	}
	ja4c := sha256_12hex(ja4cr)

	ja4 = fmt.Sprintf("%s_%s_%s", ja4a, ja4b, ja4c)
	return ja4a, ja4, nil
}

// -------------------- Server --------------------

func main() {
	log.SetFlags(0)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", outDir, err)
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("listening on %s (capture ClientHello -> full JA4)", listenAddr)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(c)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	records, ch, err := readClientHelloTLSRecords(conn, maxBytes)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		log.Printf("[%s] capture failed: %v", remote, err)
		return
	}

	ja4a, ja4, err := computeJA4FromClientHelloHandshake(ch)
	if err != nil {
		log.Printf("[%s] JA4 compute failed: %v", remote, err)
		return
	}

	now := time.Now().UTC()
	tag := fmt.Sprintf("%s_%d", now.Format("20060102T150405Z"), now.UnixNano())
	base := filepath.Join(outDir, tag)

	recordsPath := base + "_tls_records.bin"
	chPath := base + "_clienthello.bin"
	ja4aPath := base + "_ja4a.txt"
	ja4Path := base + "_ja4.txt"

	_ = os.WriteFile(recordsPath, records, 0o644)
	_ = os.WriteFile(chPath, ch, 0o644)
	_ = os.WriteFile(ja4aPath, []byte(ja4a+"\n"), 0o644)
	_ = os.WriteFile(ja4Path, []byte(ja4+"\n"), 0o644)

	// small prefix for “proof” debugging
	prefixLen := 16
	if len(ch) < prefixLen {
		prefixLen = len(ch)
	}

	log.Printf("[%s] JA4_a=%s  JA4=%s  saved=%s  ch_prefix=%s",
		remote, ja4a, ja4, base, hex.EncodeToString(ch[:prefixLen]),
	)
	// capture-only demo: close connection now
}
