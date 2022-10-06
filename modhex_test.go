package main

import (
	"bytes"
	"testing"
)

func TestModhexDecode(t *testing.T) {
	if res, err := modhexDecode("cbdefghijklnrtuv"); err != nil {
		t.Error(err)
	} else if !bytes.Equal(res, []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}) {
		t.Error("modhexDecode failed")
	}
}

func TestModhexEncode(t *testing.T) {
	if res := modhexEncode([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}); res != "cbdefghijklnrtuv" {
		t.Error("modhexEncode failed")
	}
}
