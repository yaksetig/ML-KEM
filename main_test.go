package main

import (
	"bytes"
	"testing"

	"github.com/iden3/go-iden3-crypto/constants"
)

// Test that KEM round-trip works and produces a 32-byte shared secret equal on both sides
func TestEncapsulateDecapsulate(t *testing.T) {

	// Alice generates a keypair
	dk, encKey, err := GenerateKeyPair()

	// check for error
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Bob encapsulates a (symmetric) secret
	ct, bobSS, err := Encapsulate(encKey)

	// check for errors in the encapsulation process
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Alice decapsulates the received ciphertext
	aliceSS, err := Decapsulate(dk, ct)

	// check for errors in the decapsulation process
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	// check if the shared secrets match
	if !bytes.Equal(aliceSS, bobSS) {
		t.Fatal("shared secrets do not match")
	}

	// check if shared secret is 32-bytes
	if len(aliceSS) != 32 {
		t.Fatalf("expected 32-byte secret, got %d bytes", len(aliceSS))
	}
}

// 2) Test that HKDF-SHA3 derivation is deterministic
func TestDeriveSymmetricKeyDeterministic(t *testing.T) {
	secret := make([]byte, 32)
	// fill with non-zero so you’re not testing all-zero edge case
	for i := range secret {
		secret[i] = byte(i + 1)
	}

	k1, err := DeriveSymmetricKey(secret)
	if err != nil {
		t.Fatalf("first DeriveSymmetricKey failed: %v", err)
	}
	k2, err := DeriveSymmetricKey(secret)
	if err != nil {
		t.Fatalf("second DeriveSymmetricKey failed: %v", err)
	}

	if !bytes.Equal(k1, k2) {
		t.Fatal("HKDF outputs differ on same input")
	}

	if len(k1) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(k1))
	}
}

func TestGenerateKeyDigest(t *testing.T) {

	s := []byte("Parfin is a great place to work")

	k, _ := DeriveSymmetricKey(s)

	digest1, err1 := GenerateKeyDigest(k)

	if err1 != nil {
		t.Fatalf("GenerateKeyDigest failed: %v", err1)
	}

	digest2, err2 := GenerateKeyDigest(k)

	if err2 != nil {
		t.Fatalf("GenerateKeyDigest failed: %v", err2)
	}

	if !bytes.Equal(digest1, digest2) {
		t.Fatal("Poseidon outputs differ on same input")
	}

	// TODO: Check this test is correct
	if len(digest1) < constants.Q.BitLen()/8 {
		t.Fatalf("expected digest to be at least %d bytes, got %d bytes", constants.Q.BitLen()/8, len(digest1))
	}

}
