// Package store implements the on-disk format: nonce(12) || AES-256-GCM ciphertext || tag(16).
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// Overhead is the number of bytes the format adds to the plaintext.
const Overhead = 12 + 16

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func Seal(key, plain []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plain, nil), nil
}

func Open(key, blob []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < Overhead {
		return nil, errors.New("store: blob too short")
	}
	return g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], nil)
}
