// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestVerifyMac(t *testing.T) {
	td := macData{
		Mac: digestInfo{
			Digest: []byte{0x18, 0x20, 0x3d, 0xff, 0x1e, 0x16, 0xf4, 0x92, 0xf2, 0xaf, 0xc8, 0x91, 0xa9, 0xba, 0xd6, 0xca, 0x9d, 0xee, 0x51, 0x93},
		},
		MacSalt:    []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Iterations: 2048,
	}

	message := []byte{11, 12, 13, 14, 15}
	password, _ := bmpSliceZeroTerminated([]rune(""))

	td.Mac.Algorithm.Algorithm = asn1.ObjectIdentifier([]int{1, 2, 3})
	err := verifyMac(&td, message, password)
	if _, ok := err.(NotImplementedError); !ok {
		t.Errorf("err: %v", err)
	}

	td.Mac.Algorithm.Algorithm = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	err = verifyMac(&td, message, password)
	if err != ErrIncorrectPassword {
		t.Errorf("Expected incorrect password, got err: %v", err)
	}

	password, _ = bmpSliceZeroTerminated([]rune("Sesame open"))
	err = verifyMac(&td, message, password)
	if err != nil {
		t.Errorf("err: %v", err)
	}

}

func TestComputeMac(t *testing.T) {
	td := macData{
		MacSalt:    []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Iterations: 2048,
	}

	message := []byte{11, 12, 13, 14, 15}
	password, _ := bmpSliceZeroTerminated([]rune("Sesame open"))

	td.Mac.Algorithm.Algorithm = asn1.ObjectIdentifier([]int{1, 2, 3})
	err := computeMac(&td, message, password)
	if _, ok := err.(NotImplementedError); !ok {
		t.Errorf("err: %v", err)
	}

	td.Mac.Algorithm.Algorithm = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	err = computeMac(&td, message, password)
	if err != nil {
		t.Errorf("err: %v", err)
	}

	expectedDigest := []byte{0x18, 0x20, 0x3d, 0xff, 0x1e, 0x16, 0xf4, 0x92, 0xf2, 0xaf, 0xc8, 0x91, 0xa9, 0xba, 0xd6, 0xca, 0x9d, 0xee, 0x51, 0x93}

	if bytes.Compare(td.Mac.Digest, expectedDigest) != 0 {
		t.Errorf("Computed incorrect MAC; expected MAC to be '%d' but got '%d'", expectedDigest, td.Mac.Digest)
	}

}
