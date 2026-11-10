package main

import (
	"bytes"
	"testing"

	shamir "github.com/vjebramek/goshamir"
)

func TestShareEnvelopeRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	var setID [16]byte
	copy(setID[:], []byte("test share set!!"))
	want := shamir.Shard{0x11, 0x22, 0x07}

	envelope, err := sealShare(key, setID, 3, 2, want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openShare(key, setID, 3, 2, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("openShare() = %v, want %v", got, want)
	}
}

func TestOpenShareRejectsTamperedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)
	var setID [16]byte
	copy(setID[:], []byte("test share set!!"))
	envelope, err := sealShare(key, setID, 3, 1, shamir.Shard{0x11, 0x22, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[0] ^= 0x01

	if _, err := openShare(key, setID, 3, 1, envelope); err == nil {
		t.Fatal("openShare() succeeded for tampered ciphertext")
	}
}

func TestOpenShareRejectsWrongTrustedContext(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)
	var setID [16]byte
	copy(setID[:], []byte("test share set!!"))
	envelope, err := sealShare(key, setID, 3, 1, shamir.Shard{0x11, 0x22, 0x01})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := openShare(key, setID, 2, 1, envelope); err == nil {
		t.Fatal("openShare() succeeded with the wrong expected threshold")
	}
	if _, err := openShare(key, setID, 3, 2, envelope); err == nil {
		t.Fatal("openShare() succeeded with the wrong expected share number")
	}
	setID[0] ^= 0x01
	if _, err := openShare(key, setID, 3, 1, envelope); err == nil {
		t.Fatal("openShare() succeeded with the wrong expected set ID")
	}
}
