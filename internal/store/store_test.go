package store

import (
	"bytes"
	"testing"
)

func TestRoundTripAndTamper(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	blob, err := Seal(key, []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != len("hunter2")+Overhead {
		t.Fatalf("size %d", len(blob))
	}
	got, err := Open(key, blob)
	if err != nil || string(got) != "hunter2" {
		t.Fatalf("open: %q %v", got, err)
	}
	blob[20] ^= 0xff
	if _, err := Open(key, blob); err == nil {
		t.Fatal("tampered blob accepted")
	}
	if _, err := Open(bytes.Repeat([]byte{8}, 32), mustSeal(t, key)); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func mustSeal(t *testing.T, key []byte) []byte {
	b, err := Seal(key, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
