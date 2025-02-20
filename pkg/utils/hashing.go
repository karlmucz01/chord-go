package utils

import (
	"crypto/sha1"
	"crypto/sha256"
	"errors"

	"github.com/karlmucz01/chord-go/pkg/config"
)

func HashStringSha256(input string) []byte {
	// Computes a SHA256 hash of a string
	// use cases for hashing an IP for node identifiers or a filename for key identifiers
	hashStr := sha256.Sum256([]byte(input))
	return hashStr[:8]
}

func HashStringSha1(input string) []byte {
	hashStr := sha1.Sum([]byte(input))
	return hashStr[:8]
}

func ByteSliceToUInt64(hashSlice []byte) (uint64, error) {
	// Converts a []byte slice to an Uint64 integer

	if len(hashSlice) != 8 {
		return 0, errors.New("byte slice must be of length 8")
	}

	hashUInt64 := uint64(0)
	for i := 0; i < 8; i++ {
		// set the bytes at each 8 bit interval with a byte from the slice
		hashUInt64 = (hashUInt64 << 8) | uint64(hashSlice[i])
	}
	return hashUInt64, nil
}

func ByteSliceToUint16(hashSlice []byte) (uint16, error) {
	// Converts a []byte slice to an Uint16 integer

	if len(hashSlice) != 8 {
		return 0, errors.New("byte slice must be of length 8")
	}

	hashUint16 := uint16(0)
	for i := 0; i < 8; i++ {
		// set the bytes at each 8 bit interval with a byte from the slice
		hashUint16 = (hashUint16 << 8) | uint16(hashSlice[i])
	}
	return hashUint16, nil
}

func IdentifierFromStringSha256(input string) uint64 {
	// General purpose function for passing a string and getting an identifier for the
	// identifier space
	inputHashSlice := HashStringSha256(input)           // guaranteed to return a slice of length 8
	inputUInt64, _ := ByteSliceToUInt64(inputHashSlice) // no need to capture error
	return inputUInt64 % config.IdentifierSpaceMax
}

func IdentifierFromStringSha1(input string) uint16 {
	// General purpose function for passing a string and getting an identifer for the
	// identifer space of a basic Chord implementation
	inputHashSlice := HashStringSha1(input)             // guaranteed to return a slice of length 8
	inputUint16, _ := ByteSliceToUint16(inputHashSlice) // no need to capture error
	return inputUint16 % config.BasicIdentifierSpaceMax
}
