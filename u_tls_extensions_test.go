package tls

import (
	"bytes"
	"io"
	"testing"
)

func TestTrustAnchorsExtensionEncoding(t *testing.T) {
	ext := &TrustAnchorsExtension{}
	buf := make([]byte, ext.Len())
	n, err := ext.Read(buf)
	if err != io.EOF || n != len(buf) {
		t.Fatalf("Read() = (%d, %v), want (%d, io.EOF)", n, err, len(buf))
	}
	want := []byte{0xca, 0x34, 0x00, 0x02, 0x00, 0x00}
	if !bytes.Equal(buf, want) {
		t.Fatalf("encoded trust_anchors = %x, want %x", buf, want)
	}
	if n, err := ext.Write(buf[4:]); err != nil || n != 2 {
		t.Fatalf("Write(empty list) = (%d, %v), want (2, nil)", n, err)
	}
	if _, err := ext.Write([]byte{0x00, 0x01, 0x00}); err == nil {
		t.Fatal("Write(non-empty list) unexpectedly succeeded")
	}
}

func TestTrustAnchorsExtensionRoundTrip(t *testing.T) {
	if _, ok := ExtensionFromID(extensionTrustAnchors).(*TrustAnchorsExtension); !ok {
		t.Fatal("ExtensionFromID did not return TrustAnchorsExtension")
	}
	m := &clientHelloMsg{
		vers:               VersionTLS13,
		random:             make([]byte, 32),
		cipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		compressionMethods: []uint8{compressionNone},
		trustAnchors:       true,
	}
	encoded, err := m.marshalMsg(false)
	if err != nil {
		t.Fatalf("marshalMsg() error: %v", err)
	}
	var decoded clientHelloMsg
	if !decoded.unmarshal(encoded) {
		t.Fatal("unmarshal() rejected a valid trust_anchors extension")
	}
	if !decoded.trustAnchors {
		t.Fatal("unmarshal() did not preserve trust_anchors")
	}
}
