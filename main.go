package main

import (
	"bytes"
	"crypto/mlkem"
	"crypto/sha3"
	"hash"
	"io"
	"log"
	"math/big"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"golang.org/x/crypto/hkdf"
)

// GenerateKeyPair is a function that generates an ML-KEM 768 keypair
// receives nothing
// returns an ML-KEM keypair (i.e., a decapsulation key and an encapsulation key), and an error
func GenerateKeyPair() (*mlkem.DecapsulationKey768, []byte, error) {

	dk, err := mlkem.GenerateKey768()

	if err != nil {
		return nil, nil, err
	}

	return dk, dk.EncapsulationKey().Bytes(), nil
}

// Encapsulate uses Alice's encapsulation key to produce
// receives an encapsulation key
// returns a ciphertext, the freshly generaed shared secret, and an error
func Encapsulate(encapsulationKey []byte) ([]byte, []byte, error) {

	ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)

	if err != nil {
		return nil, nil, err
	}

	sharedSecret, ciphertext := ek.Encapsulate()

	return ciphertext, sharedSecret, nil
}

// IMPORTANT NOTE:
// ML-KEM has non-zero probability of failure, meaning two honest parties may derive different shared secrets. This causes handshake failure.
// ML-KEM has a cryptographically small failure rate less than 2^-138; Clients should retry if a failure is encountered.

// Decapsulate takes Alice's DecapsulationKey and Bob's ciphertext
// receives a decapsulation key and ciphertext
// returns a (decapsulated) shared secret and an error
func Decapsulate(dk *mlkem.DecapsulationKey768, ciphertext []byte) ([]byte, error) {

	secret, err := dk.Decapsulate(ciphertext)

	// check for errors in the decapsulation process
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// DeriveSymmetricKey derives from a shared secret, a symmetric key for subsequent encryption
// receives a shared seret (with potentially low entropy)
// returns a symmetric key (with more entropy) and an error
func DeriveSymmetricKey(sharedSecret []byte) ([]byte, error) {

	// public context for HKDF
	context := []byte("Rayls")

	reader := hkdf.New(func() hash.Hash { return sha3.New256() }, sharedSecret, nil, context)

	key := make([]byte, 32)

	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}

	return key, nil
}

// GenerateKeyDigest takes a shared secret and generates a key digest to be posted as an identifier
// receives an initial shared secret ([]byte)
// returns the Poseidon hash of the secret and an error
func GenerateKeyDigest(secret []byte) ([]byte, error) {

	// create a new big.Int
	z := new(big.Int)

	// set the value of z (big.Int) to the shared secret ([]byte)
	z.SetBytes(secret)

	// reduce it to fit in the field
	z.Mod(z, constants.Q)

	inputs := []*big.Int{z}

	digest, err := poseidon.Hash(inputs)

	if err != nil {
		return nil, err
	}

	return digest.Bytes(), nil
}

// NOTE: THIS IS NOT CHECKING FOR ERRORS IN EACH STEP.
// THIS IS JUST A DEMO OF HOW TO USE THE FUNCTIONS TO HAVE CLEARER CODE
func main() {

	// A generates a KEM keypair
	decapsulationKey, encapsulationKey, _ := GenerateKeyPair()

	// B encapsulates a shared secret using A’s public key (encapsulation key)
	ciphertext, secretB, _ := Encapsulate(encapsulationKey)

	// In this protocol, B has to publish the digest of the key on the commit chain
	sharedSecret, _ := DeriveSymmetricKey(secretB)
	_, _ = GenerateKeyDigest(sharedSecret)

	// A decapsulates the ciphertext
	secretA, _ := Decapsulate(decapsulationKey, ciphertext)

	// 4) Both sides derive the same 32-byte key via HKDF-SHA3-256 with context "Rayls"
	symmetricKeyA, _ := DeriveSymmetricKey(secretA)

	// B derives the same key
	symmetricKeyB, _ := DeriveSymmetricKey(secretB)

	// Verify equality
	if !bytes.Equal(symmetricKeyA, symmetricKeyB) {
		log.Fatal("derived keys do not match")
	}

}
