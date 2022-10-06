package main

import (
	"errors"
	"regexp"
	"strings"
)

const moxhexAlphabet = "cbdefghijklnrtuv"

var validModHex = regexp.MustCompile(`^[cbdefghijklnrtuv]+$`)

func modhexEncode(data []byte) string {
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = moxhexAlphabet[b>>4]
		result[i*2+1] = moxhexAlphabet[b&0x0f]
	}
	return string(result)
}

func modhexDecode(data string) ([]byte, error) {
	if !validModHex.MatchString(data) || len(data)%2 != 0 {
		return nil, errors.New("invalid modhex data")
	}
	result := make([]byte, len(data)/2)
	for i, b := range data {
		result[i/2] <<= 4
		result[i/2] += byte(strings.IndexRune(moxhexAlphabet, b))
	}
	return result, nil
}
