package main

// Local OHTTP gateway for debug traffic inspection via Proxyman.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	kemID  = uint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
	kdfID  = uint16(0x0001) // HKDF-SHA256
	aeadID = uint16(0x0001) // AES-128-GCM

	encLen           = 32 // X25519 enc length
	ohttpHeaderLen   = 7  // key_id(1) + kem_id(2) + kdf_id(2) + aead_id(2)
	responseNonceLen = 16 // max(Nn=12, Nk=16) per RFC 9458 §4.6.2
)

// suiteID values per RFC 9180.
var (
	kemSuiteID  = []byte{0x4B, 0x45, 0x4D, 0x00, 0x20}
	hpkeSuiteID = []byte{0x48, 0x50, 0x4B, 0x45, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01}
)

// ── HPKE receiver (RFC 9180) ──────────────────────────────────────────────────

type ReceiverContext struct {
	key            []byte
	baseNonce      []byte
	exporterSecret []byte
	Enc            []byte // client ephemeral X25519 public key
}

func SetupBaseR(privKey *ecdh.PrivateKey, enc, info []byte) (*ReceiverContext, error) {
	senderPub, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, fmt.Errorf("invalid enc: %w", err)
	}
	dh, err := privKey.ECDH(senderPub)
	if err != nil {
		return nil, fmt.Errorf("X25519 failed: %w", err)
	}
	sharedSecret := extractAndExpand(dh, concat(enc, privKey.PublicKey().Bytes()))
	key, baseNonce, expSec := keySchedule(sharedSecret, info)
	return &ReceiverContext{key: key, baseNonce: baseNonce, exporterSecret: expSec, Enc: enc}, nil
}

// Open decrypts with AES-128-GCM, empty AAD, seq=0 nonce (RFC 9180 §5.2).
func (r *ReceiverContext) Open(ciphertext []byte) ([]byte, error) {
	block, _ := aes.NewCipher(r.key)
	gcm, _ := cipher.NewGCM(block)
	return gcm.Open(nil, r.baseNonce, ciphertext, nil)
}

// Export derives a secret via LabeledExpand (RFC 9180 §5.3).
func (r *ReceiverContext) Export(exporterContext []byte, length int) []byte {
	return labeledExpand(hpkeSuiteID, r.exporterSecret, "sec", exporterContext, length)
}

func extractAndExpand(dh, kemContext []byte) []byte {
	return labeledExpand(kemSuiteID, labeledExtract(kemSuiteID, nil, "eae_prk", dh), "shared_secret", kemContext, 32)
}

func keySchedule(sharedSecret, info []byte) (key, baseNonce, exporterSecret []byte) {
	ksContext := concat([]byte{0x00},
		labeledExtract(hpkeSuiteID, nil, "psk_id_hash", nil),
		labeledExtract(hpkeSuiteID, nil, "info_hash", info),
	)
	secret := labeledExtract(hpkeSuiteID, sharedSecret, "secret", nil)
	return labeledExpand(hpkeSuiteID, secret, "key", ksContext, 16),
		labeledExpand(hpkeSuiteID, secret, "base_nonce", ksContext, 12),
		labeledExpand(hpkeSuiteID, secret, "exp", ksContext, 32)
}

// LabeledExtract: HKDF-Extract(salt, "HPKE-v1"||suiteID||label||ikm)
func labeledExtract(suiteID, salt []byte, label string, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = nil
	}
	return hkdf.Extract(sha256.New, concat([]byte("HPKE-v1"), suiteID, []byte(label), ikm), salt)
}

// LabeledExpand: HKDF-Expand(prk, I2OSP(L,2)||"HPKE-v1"||suiteID||label||info, L)
func labeledExpand(suiteID, prk []byte, label string, info []byte, length int) []byte {
	li := concat([]byte{byte(length >> 8), byte(length)}, []byte("HPKE-v1"), suiteID, []byte(label), info)
	out := make([]byte, length)
	io.ReadFull(hkdf.Expand(sha256.New, prk, li), out) //nolint:errcheck
	return out
}

func concat(slices ...[]byte) []byte {
	n := 0
	for _, s := range slices {
		n += len(s)
	}
	out := make([]byte, 0, n)
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}

// ── OHTTP gateway (RFC 9458) ──────────────────────────────────────────────────

type OhttpGateway struct {
	keyID      byte
	privateKey *ecdh.PrivateKey
}

func NewOhttpGateway() (*OhttpGateway, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &OhttpGateway{keyID: 0x01, privateKey: priv}, nil
}

// KeyConfig returns the 41-byte OHTTP key config (RFC 9458 §3).
func (gw *OhttpGateway) KeyConfig() []byte {
	pub := gw.privateKey.PublicKey().Bytes()
	cfg := []byte{gw.keyID, byte(kemID >> 8), byte(kemID)}
	cfg = append(cfg, pub...)
	return append(cfg, 0x00, 0x04, byte(kdfID>>8), byte(kdfID), byte(aeadID>>8), byte(aeadID))
}

// Decapsulate decrypts an OHTTP request, returning the receiver context and plaintext BHTTP bytes.
func (gw *OhttpGateway) Decapsulate(body []byte) (*ReceiverContext, []byte, error) {
	if len(body) < ohttpHeaderLen+encLen+1 {
		return nil, nil, fmt.Errorf("request too short: %d bytes", len(body))
	}
	hdr := body[:ohttpHeaderLen]
	if hdr[0] != gw.keyID ||
		uint16(hdr[1])<<8|uint16(hdr[2]) != kemID ||
		uint16(hdr[3])<<8|uint16(hdr[4]) != kdfID ||
		uint16(hdr[5])<<8|uint16(hdr[6]) != aeadID {
		return nil, nil, fmt.Errorf("unsupported suite or unknown key_id=%d", hdr[0])
	}
	ctx, err := SetupBaseR(gw.privateKey, body[ohttpHeaderLen:ohttpHeaderLen+encLen],
		buildHpkeInfo(hdr[0], kemID, kdfID, aeadID))
	if err != nil {
		return nil, nil, fmt.Errorf("HPKE setup: %w", err)
	}
	plain, err := ctx.Open(body[ohttpHeaderLen+encLen:])
	return ctx, plain, err
}

// EncapsulateResponse encrypts a BHTTP response using plain (non-labeled) HKDF per RFC 9458 §4.4.
func (gw *OhttpGateway) EncapsulateResponse(ctx *ReceiverContext, bhttpResponse []byte) ([]byte, error) {
	exported := ctx.Export([]byte("message/bhttp response"), responseNonceLen)
	responseNonce := make([]byte, responseNonceLen)
	if _, err := rand.Read(responseNonce); err != nil {
		return nil, err
	}
	prk := hkdf.Extract(sha256.New, exported, concat(ctx.Enc, responseNonce))

	aeadKey, aeadNonce := make([]byte, 16), make([]byte, 12)
	io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("key")), aeadKey)     //nolint:errcheck
	io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("nonce")), aeadNonce) //nolint:errcheck

	block, _ := aes.NewCipher(aeadKey)
	gcm, _ := cipher.NewGCM(block)
	return concat(responseNonce, gcm.Seal(nil, aeadNonce, bhttpResponse, nil)), nil
}

// buildHpkeInfo: "message/bhttp request\x00" || key_id(1) || kem(2) || kdf(2) || aead(2)
func buildHpkeInfo(keyID byte, kem, kdf, aead uint16) []byte {
	return append([]byte("message/bhttp request\x00"),
		keyID, byte(kem>>8), byte(kem), byte(kdf>>8), byte(kdf), byte(aead>>8), byte(aead))
}

// ── BHTTP (RFC 9292, Known-Length framing) ────────────────────────────────────

type BhttpRequest struct {
	Method, Scheme, Authority, Path string
	Headers                         [][2]string
	Body                            []byte
}

func ParseBhttpRequest(data []byte) (*BhttpRequest, error) {
	off := 0
	framing, n, err := readVarint(data, off)
	if err != nil || framing != 0 {
		return nil, fmt.Errorf("expected known-length request (framing=0)")
	}
	off += n

	read := func(label string) ([]byte, error) {
		v, n, e := readVarField(data, off)
		if e != nil {
			return nil, fmt.Errorf("%s: %w", label, e)
		}
		off += n
		return v, nil
	}

	method, err := read("method")
	if err != nil {
		return nil, err
	}
	scheme, err := read("scheme")
	if err != nil {
		return nil, err
	}
	authority, err := read("authority")
	if err != nil {
		return nil, err
	}
	path, err := read("path")
	if err != nil {
		return nil, err
	}

	hSectionLen, n, _ := readVarint(data, off)
	if err != nil {
		return nil, fmt.Errorf("header section length: %w", err)
	}
	off += n
	hEnd := off + int(hSectionLen)
	if hEnd > len(data) {
		return nil, fmt.Errorf("header section out of bounds")
	}
	var headers [][2]string
	for off < hEnd {
		name, nn, e := readVarField(data, off)
		if e != nil {
			return nil, fmt.Errorf("header name: %w", e)
		}
		off += nn
		value, nv, e := readVarField(data, off)
		if e != nil {
			return nil, fmt.Errorf("header value: %w", e)
		}
		off += nv
		headers = append(headers, [2]string{string(name), string(value)})
	}

	cLen, n, _ := readVarint(data, off)
	if err != nil {
		return nil, fmt.Errorf("content length: %w", err)
	}
	off += n
	if off+int(cLen) > len(data) {
		return nil, fmt.Errorf("body out of bounds")
	}
	body := make([]byte, cLen)
	copy(body, data[off:off+int(cLen)])

	return &BhttpRequest{
		Method: string(method), Scheme: string(scheme),
		Authority: string(authority), Path: string(path),
		Headers: headers, Body: body,
	}, nil
}

func SerializeBhttpRequest(method, scheme, authority, path string, headers [][2]string, body []byte) []byte {
	var buf []byte
	buf = appendVarint(buf, 0)
	buf = appendVarField(buf, []byte(method))
	buf = appendVarField(buf, []byte(scheme))
	buf = appendVarField(buf, []byte(authority))
	buf = appendVarField(buf, []byte(path))
	var hdrBuf []byte
	for _, h := range headers {
		hdrBuf = appendVarField(hdrBuf, []byte(strings.ToLower(h[0])))
		hdrBuf = appendVarField(hdrBuf, []byte(h[1]))
	}
	buf = appendVarint(buf, uint64(len(hdrBuf)))
	buf = append(buf, hdrBuf...)
	buf = appendVarField(buf, body)
	return appendVarint(buf, 0)
}

func SerializeBhttpResponse(statusCode int, headers [][2]string, body []byte) []byte {
	var buf []byte
	buf = appendVarint(buf, 1)
	buf = appendVarint(buf, uint64(statusCode))
	var hdrBuf []byte
	for _, h := range headers {
		hdrBuf = appendVarField(hdrBuf, []byte(h[0]))
		hdrBuf = appendVarField(hdrBuf, []byte(h[1]))
	}
	buf = appendVarint(buf, uint64(len(hdrBuf)))
	buf = append(buf, hdrBuf...)
	buf = appendVarField(buf, body)
	return appendVarint(buf, 0)
}

// QUIC variable-length integers (RFC 9000 §16).
func readVarint(data []byte, offset int) (uint64, int, error) {
	if offset >= len(data) {
		return 0, 0, fmt.Errorf("varint out of bounds at %d", offset)
	}
	b := data[offset]
	switch b >> 6 {
	case 0:
		return uint64(b & 0x3F), 1, nil
	case 1:
		if offset+1 >= len(data) {
			return 0, 0, fmt.Errorf("2-byte varint out of bounds")
		}
		return uint64(b&0x3F)<<8 | uint64(data[offset+1]), 2, nil
	case 2:
		if offset+3 >= len(data) {
			return 0, 0, fmt.Errorf("4-byte varint out of bounds")
		}
		return uint64(b&0x3F)<<24 | uint64(data[offset+1])<<16 | uint64(data[offset+2])<<8 | uint64(data[offset+3]), 4, nil
	default:
		if offset+7 >= len(data) {
			return 0, 0, fmt.Errorf("8-byte varint out of bounds")
		}
		v := uint64(b & 0x3F)
		for i := 1; i <= 7; i++ {
			v = v<<8 | uint64(data[offset+i])
		}
		return v, 8, nil
	}
}

func appendVarint(buf []byte, v uint64) []byte {
	switch {
	case v < 0x40:
		return append(buf, byte(v))
	case v < 0x4000:
		return append(buf, 0x40|byte(v>>8), byte(v))
	case v < 0x40000000:
		return append(buf, 0x80|byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(buf, 0xC0|byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

func readVarField(data []byte, offset int) ([]byte, int, error) {
	length, n, err := readVarint(data, offset)
	if err != nil {
		return nil, 0, err
	}
	start, end := offset+n, offset+n+int(length)
	if end > len(data) {
		return nil, 0, fmt.Errorf("field [%d:%d] out of bounds", start, end)
	}
	return data[start:end], n + int(length), nil
}

func appendVarField(buf, data []byte) []byte {
	return append(appendVarint(buf, uint64(len(data))), data...)
}

// ── HTTP server ───────────────────────────────────────────────────────────────

var hopByHopHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "transfer-encoding": true,
	"upgrade": true, "proxy-authenticate": true, "proxy-authorization": true,
	"te": true, "trailers": true,
}

func main() {
	gw, err := NewOhttpGateway()
	if err != nil {
		log.Fatalf("gateway init: %v", err)
	}
	port := "8443"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}
	client := buildForwardClient()

	mux := http.NewServeMux()
	mux.HandleFunc("/ohttp-key/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/ohttp-keys")
		w.Header().Set("Cache-Control", "max-age=300")
		w.Write(gw.KeyConfig()) //nolint:errcheck
	})
	mux.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(gw, client, w, r)
	})

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("Local OHTTP gateway: https://localhost:%s  (Proxyman → local-ohttp client for plaintext)", port)
	log.Fatal(http.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{generateSelfSignedCert()}}), mux))
}

func handleRequest(gw *OhttpGateway, client *http.Client, w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	ctx, bhttpReqBytes, err := gw.Decapsulate(body)
	if err != nil {
		log.Printf("decapsulate: %v", err)
		http.Error(w, "decapsulation failed", http.StatusBadRequest)
		return
	}
	inner, err := ParseBhttpRequest(bhttpReqBytes)
	if err != nil {
		log.Printf("bhttp parse: %v", err)
		http.Error(w, "malformed bhttp", http.StatusBadRequest)
		return
	}
	log.Printf("→ %s %s://%s%s", inner.Method, inner.Scheme, inner.Authority, inner.Path)

	status, headers, respBody, err := forwardRequest(client, inner)
	if err != nil {
		log.Printf("forward: %v", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	log.Printf("← %d (%d bytes)", status, len(respBody))

	encResp, err := gw.EncapsulateResponse(ctx, SerializeBhttpResponse(status, headers, respBody))
	if err != nil {
		log.Printf("encapsulate response: %v", err)
		http.Error(w, "encapsulation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "message/ohttp-res")
	w.Write(encResp) //nolint:errcheck
}

func forwardRequest(client *http.Client, inner *BhttpRequest) (int, [][2]string, []byte, error) {
	req, err := http.NewRequest(inner.Method, inner.Scheme+"://"+inner.Authority+inner.Path, bytes.NewReader(inner.Body))
	if err != nil {
		return 0, nil, nil, err
	}
	for _, h := range inner.Headers {
		if strings.ToLower(h[0]) == "host" {
			req.Host = h[1]
		} else {
			req.Header.Add(h[0], h[1])
		}
	}
	if req.Host == "" {
		req.Host = inner.Authority
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, err
	}
	var headers [][2]string
	for name, values := range resp.Header {
		lower := strings.ToLower(name)
		if hopByHopHeaders[lower] || lower == "content-length" {
			continue
		}
		for _, v := range values {
			headers = append(headers, [2]string{lower, v})
		}
	}
	return resp.StatusCode, headers, respBody, nil
}

func buildForwardClient() *http.Client {
	proxyFunc := http.ProxyFromEnvironment
	if os.Getenv("HTTPS_PROXY") == "" && os.Getenv("https_proxy") == "" {
		const defaultProxy = "http://127.0.0.1:9090"
		proxyFunc = func(_ *http.Request) (*url.URL, error) { return url.Parse(defaultProxy) }
		log.Printf("HTTPS_PROXY not set; defaulting to %s", defaultProxy)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           proxyFunc,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Timeout: 60 * time.Second,
	}
}

func generateSelfSignedCert() tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
}
