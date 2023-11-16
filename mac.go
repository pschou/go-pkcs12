// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"hash"

	"golang.org/x/crypto/sha3"
)

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

// from PKCS#7:
type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

var (
	OidSHA1          = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	OidSHA256        = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1})
	OidSHA384        = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2})
	OidSHA512        = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3})
	OidSHA256_224    = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 4})
	OidSHA512_224    = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 5})
	OidSHA512_256    = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 6})
	OidSHA3_224      = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 7})
	OidSHA3_256      = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 8})
	OidSHA3_384      = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 9})
	OidSHA3_512      = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 10})
	OidSHA3_SHAKE128 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 11})
	OidSHA3_SHAKE256 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 12})
)

func doMac(macData *macData, message, password []byte) ([]byte, error) {
	var hFn func() hash.Hash
	var key []byte
	switch {
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA1):
		hFn = sha1.New
		key = pbkdf(hFn, 20, 64, macData.MacSalt, password, macData.Iterations, 3, 20)
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA256):
		hFn = sha256.New
		key = pbkdf(hFn, 32, 64, macData.MacSalt, password, macData.Iterations, 3, 32)
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA384):
		hFn = sha512.New384
		key = pbkdf(hFn, 48, 64, macData.MacSalt, password, macData.Iterations, 3, 32)
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA512):
		hFn = sha512.New
		key = pbkdf(hFn, 64, 64, macData.MacSalt, password, macData.Iterations, 3, 32)
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA256_224):
		hFn = sha256.New224
		key = pbkdf(hFn, 28, 64, macData.MacSalt, password, macData.Iterations, 3, 28)
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA512_224):
		hFn = sha512.New512_224
		key = pbkdf(hFn, 28, 64, macData.MacSalt, password, macData.Iterations, 3, 28)
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA512_256):
		hFn = sha512.New512_256
		key = pbkdf(hFn, 32, 64, macData.MacSalt, password, macData.Iterations, 3, 32)
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA3_224):
		hFn = sha3.New224
		key = pbkdf(hFn, 28, 64, macData.MacSalt, password, macData.Iterations, 3, 28)
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA3_256):
		hFn = sha3.New256
		key = pbkdf(hFn, 32, 64, macData.MacSalt, password, macData.Iterations, 3, 32)
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA3_384):
		hFn = sha3.New384
		key = pbkdf(hFn, 48, 64, macData.MacSalt, password, macData.Iterations, 3, 32)
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA3_512):
		hFn = sha3.New512
		key = pbkdf(hFn, 64, 64, macData.MacSalt, password, macData.Iterations, 3, 32)
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA3_SHAKE128):
		hFn = NewShake128
		key = pbkdf(hFn, 16, 64, macData.MacSalt, password, macData.Iterations, 3, 16)
	case macData.Mac.Algorithm.Algorithm.Equal(OidSHA3_SHAKE256):
		hFn = NewShake256
		key = pbkdf(hFn, 32, 64, macData.MacSalt, password, macData.Iterations, 3, 32)
	default:
		return nil, NotImplementedError("unknown digest algorithm: " + macData.Mac.Algorithm.Algorithm.String())
	}
	defer func() {
		for i, _ := range key {
			key[i] = 0
		}
	}()

	mac := hmac.New(hFn, key)
	mac.Write(message)
	return mac.Sum(nil), nil
}

func verifyMac(macData *macData, message, password []byte) error {
	expectedMAC, err := doMac(macData, message, password)
	if err != nil {
		return err
	}
	if !hmac.Equal(macData.Mac.Digest, expectedMAC) {
		return ErrIncorrectPassword
	}
	return nil
}

func computeMac(macData *macData, message, password []byte) error {
	digest, err := doMac(macData, message, password)
	if err != nil {
		return err
	}
	macData.Mac.Digest = digest
	return nil
}
