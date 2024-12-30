package utils

import (
	"crypto/sha256"
	"errors"

	"github.com/karlmucz01/chord-go/pkg/config"
)

func HashString(input string) []byte {
	// Computes a SHA256 hash of a string
	// use cases for hashing an IP for node identifiers or a filename for key identifiers
	hashStr := sha256.Sum256([]byte(input))
	return hashStr[:8]
}

func ByteSliceToUInt64(hashSlice []byte) (uint64, error) {
	// Converts a []byte slice to an Integer

	if len(hashSlice) != 8 {
		return 0, errors.New("byte slice must be of length 8")
	}

	hashUInt64 := uint64(0)
	for i := 0; i < 8; i++ {
		hashUInt64 = (hashUInt64 << 8) | uint64(hashSlice[i])
	}
	return hashUInt64, nil
}

func IdentifierFromString(input string) uint64 {
	// General purpose function for passing a string and getting an identifier for the
	// identifier space
	inputHashSlice := HashString(input)                 // guaranteed to return a slice of length 8
	inputUInt64, _ := ByteSliceToUInt64(inputHashSlice) // no need to capture error
	return inputUInt64 % config.IdentifierSpaceMax
}
