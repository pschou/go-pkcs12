// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"errors"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxRune  = '\U0010FFFF' // Maximum valid Unicode code point.
	surrSelf = 0x10000
)

// bmpSliceZeroTerminated returns s encoded in UCS-2 with a zero terminator.
func bmpSliceZeroTerminated(s []rune) (ret []byte, err error) {
	// References:
	// https://tools.ietf.org/html/rfc7292#appendix-B.1
	// The above RFC provides the info that BMPSlices are NULL terminated.

	ret, err = bmpSlice(s)
	if err == nil {
		ret = append(ret, 0, 0)
	}
	//fmt.Printf("bmp0: %#v\n", ret)
	return
}

// bmpSlice returns s encoded in UCS-2 with a zero terminator.
func bmpSlice(s []rune) (ret []byte, err error) {
	// References:
	// https://tools.ietf.org/html/rfc7292#appendix-B.1
	// The above RFC provides the info that BMPSlices are NULL terminated.

	for _, r := range s {
		if !(r < surrSelf || r > maxRune) { // bad character
			err = errors.New("pkcs12: string contains characters that cannot be encoded in UCS-2")
			return
		}
	}

	ret = make([]byte, 2*len(s), 2*len(s)+2)

	tmp := utf16.Encode(s)
	for i, r := range tmp {
		ret[2*i], ret[2*i+1], tmp[i] = byte(r>>8), byte(r&0xff), 0
	}
	//fmt.Printf("bmp: %#v\n", ret)
	return
}

// bmpString returns s encoded in UCS-2
func bmpString(s string) ([]byte, error) {
	// References:
	// https://tools.ietf.org/html/rfc7292#appendix-B.1
	// https://en.wikipedia.org/wiki/Plane_(Unicode)#Basic_Multilingual_Plane
	//  - non-BMP characters are encoded in UTF 16 by using a surrogate pair of 16-bit codes
	//	  EncodeRune returns 0xfffd if the rune does not need special encoding

	ret := make([]byte, 0, 2*len(s)+2)

	for _, r := range s {
		if t, _ := utf16.EncodeRune(r); t != 0xfffd {
			return nil, errors.New("pkcs12: string contains characters that cannot be encoded in UCS-2")
		}
		ret = append(ret, byte(r/256), byte(r%256))
	}

	return ret, nil
}

func decodeBMPString(bmpString []byte) (string, error) {
	if len(bmpString)%2 != 0 {
		return "", errors.New("pkcs12: odd-length BMP string")
	}

	// strip terminator if present
	if l := len(bmpString); l >= 2 && bmpString[l-1] == 0 && bmpString[l-2] == 0 {
		bmpString = bmpString[:l-2]
	}

	s := make([]uint16, 0, len(bmpString)/2)
	for len(bmpString) > 0 {
		s = append(s, uint16(bmpString[0])<<8+uint16(bmpString[1]))
		bmpString = bmpString[2:]
	}

	return string(utf16.Decode(s)), nil
}

func decodeBMPSlice(bmpString []byte) ([]byte, error) {
	if len(bmpString)%2 != 0 {
		return nil, errors.New("pkcs12: odd-length BMP string")
	}

	// strip terminator if present
	if l := len(bmpString); l >= 2 && bmpString[l-1] == 0 && bmpString[l-2] == 0 {
		bmpString = bmpString[:l-2]
	}

	s, n := make([]byte, len(bmpString)*4), 0
	r := rune(0)
	u16 := []uint16{0}
	for len(bmpString) > 0 {
		u16[0] = uint16(bmpString[0])<<8 + uint16(bmpString[1])
		r = utf16.Decode(u16)[0]
		n += utf8.EncodeRune(s[n:], r)
		bmpString = bmpString[2:]
	}

	return s[:n], nil
}
