package main

import "testing"

// synthetic DER: SEQUENCE { "com.apple.security.cs.allow-jit" = TRUE,
//
//	"com.foo" = "ABC123",
//	"com.list" = {"a","b"} }
func TestDecodeDEREntitlements(t *testing.T) {
	key1 := "com.apple.security.cs.allow-jit"
	blob := []byte{
		0x30, 0x40, // SEQUENCE, len 64
	}
	blob = append(blob, 0x0c, byte(len(key1)))
	blob = append(blob, key1...)
	blob = append(blob, 0x01, 0x01, 0xff) // BOOLEAN true

	key2 := "com.foo"
	val2 := "ABC123"
	blob = append(blob, 0x0c, byte(len(key2)))
	blob = append(blob, key2...)
	blob = append(blob, 0x0c, byte(len(val2)))
	blob = append(blob, val2...)

	key3 := "com.list"
	inner := []byte{0x31, 0x06, 0x0c, 0x01, 'a', 0x0c, 0x01, 'b'}
	blob = append(blob, 0x0c, byte(len(key3)))
	blob = append(blob, key3...)
	blob = append(blob, inner...)

	// fix outer length
	blob[1] = byte(len(blob) - 2)

	got := decodeDEREntitlements(blob)
	if got[key1] != "true" {
		t.Fatalf("key1: got %q want true", got[key1])
	}
	if got[key2] != "ABC123" {
		t.Fatalf("key2: got %q want ABC123", got[key2])
	}
	if got[key3] != "[a, b]" {
		t.Fatalf("key3: got %q want [a, b]", got[key3])
	}
}
