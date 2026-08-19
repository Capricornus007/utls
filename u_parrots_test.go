package tls

import (
	"bytes"
	"net"
	"testing"
)

type incrementingSource struct {
	next byte
}

func (s *incrementingSource) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = s.next
		s.next++
	}
	return len(b), nil
}

func findKeyShareExtension(t *testing.T, exts []TLSExtension) *KeyShareExtension {
	t.Helper()

	for _, ext := range exts {
		if keyShareExt, ok := ext.(*KeyShareExtension); ok {
			return keyShareExt
		}
	}

	t.Fatal("key_share extension not found")
	return nil
}

func findKeyShareData(t *testing.T, keyShareExt *KeyShareExtension, group CurveID) []byte {
	t.Helper()

	for _, keyShare := range keyShareExt.KeyShares {
		if keyShare.Group == group {
			return keyShare.Data
		}
	}

	t.Fatalf("key_share for group %v not found", group)
	return nil
}

func newTestUConnWithIncrementingRand() *UConn {
	return UClient(&net.TCPConn{}, &Config{
		ServerName: "example.com",
		Rand:       &incrementingSource{},
	}, HelloCustom)
}

func TestParrotFingerprintsReuseHybridClassicalKeyShare(t *testing.T) {
	spec, err := UTLSIdToSpec(HelloFirefox_148)
	if err != nil {
		t.Fatalf("unexpected error creating Firefox 148 spec: %v", err)
	}

	uconn := newTestUConnWithIncrementingRand()
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("unexpected error applying Firefox 148 spec: %v", err)
	}

	keyShareExt := findKeyShareExtension(t, uconn.Extensions)
	hybridData := findKeyShareData(t, keyShareExt, X25519MLKEM768)
	classicalData := findKeyShareData(t, keyShareExt, X25519)

	if len(hybridData) < x25519PublicKeySize {
		t.Fatalf("hybrid keyshare is too short: got %d bytes", len(hybridData))
	}
	hybridClassicalPart := hybridData[len(hybridData)-x25519PublicKeySize:]
	if !bytes.Equal(hybridClassicalPart, classicalData) {
		t.Fatal("expected Firefox 148 hybrid/classical keyshares to reuse the same public key")
	}

	keys := uconn.HandshakeState.State13.KeyShareKeys
	if keys == nil || keys.MlkemEcdhe == nil || keys.Ecdhe == nil {
		t.Fatal("expected both hybrid and classical ECDHE private keys to be set")
	}
	if keys.MlkemEcdhe != keys.Ecdhe {
		t.Fatal("expected Firefox 148 hybrid/classical keyshares to reuse the same ECDHE private key")
	}
}

func TestHybridClassicalKeySharesAreIndependentByDefault(t *testing.T) {
	spec := ClientHelloSpec{
		TLSVersMin: VersionTLS12,
		TLSVersMax: VersionTLS13,
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
		},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&SupportedCurvesExtension{Curves: []CurveID{
				X25519MLKEM768,
				X25519,
			}},
			&KeyShareExtension{KeyShares: []KeyShare{
				{Group: X25519MLKEM768},
				{Group: X25519},
			}},
			&SupportedVersionsExtension{Versions: []uint16{
				VersionTLS13,
				VersionTLS12,
			}},
		},
	}

	uconn := newTestUConnWithIncrementingRand()
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("unexpected error applying independent keyshare spec: %v", err)
	}

	keyShareExt := findKeyShareExtension(t, uconn.Extensions)
	hybridData := findKeyShareData(t, keyShareExt, X25519MLKEM768)
	classicalData := findKeyShareData(t, keyShareExt, X25519)

	if len(hybridData) < x25519PublicKeySize {
		t.Fatalf("hybrid keyshare is too short: got %d bytes", len(hybridData))
	}
	hybridClassicalPart := hybridData[len(hybridData)-x25519PublicKeySize:]
	if bytes.Equal(hybridClassicalPart, classicalData) {
		t.Fatal("expected independent keyshares by default")
	}

	keys := uconn.HandshakeState.State13.KeyShareKeys
	if keys == nil || keys.MlkemEcdhe == nil || keys.Ecdhe == nil {
		t.Fatal("expected both hybrid and classical ECDHE private keys to be set")
	}
	if keys.MlkemEcdhe == keys.Ecdhe {
		t.Fatal("expected independent ECDHE private keys by default")
	}
}
