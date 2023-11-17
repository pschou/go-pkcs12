// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
)

var (
	// see https://tools.ietf.org/html/rfc7292#appendix-D
	oidCertTypeX509Certificate = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 22, 1})
	oidKeyBag                  = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 1})
	oidPKCS8ShroundedKeyBag    = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 2})
	oidCertBag                 = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 3})
)

type certBag struct {
	Id   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

// Function which decodes a keybag, for use in a Custom Key Decoder with a string input (password)
func DecodePkcs8ShroudedKeyBagWithPassword(asn1Data []byte, password []rune) (privateKey interface{}, algorithm, PBES2HMACAlgorithm, PBES2EncryptionAlgorithm asn1.ObjectIdentifier, salt []byte, err error) {
	var encodedPassword []byte
	encodedPassword, err = bmpSliceZeroTerminated(password)
	if err != nil {
		return
	}
	defer func() {
		for i, _ := range encodedPassword {
			encodedPassword[i] = 0
		}
	}()
	return decodePkcs8ShroudedKeyBag(asn1Data, encodedPassword)
}

// Function which decodes a keybag, for use in a Custom Key Decoder
func decodePkcs8ShroudedKeyBag(asn1Data []byte, bmpPassword []byte) (privateKey interface{}, algorithm, PBES2HMACAlgorithm, PBES2EncryptionAlgorithm asn1.ObjectIdentifier, salt []byte, err error) {
	pkinfo := new(encryptedPrivateKeyInfo)
	if err = unmarshal(asn1Data, pkinfo); err != nil {
		err = errors.New("pkcs12: error decoding PKCS#8 shrouded key bag: " + err.Error())
		return
	}

	var pkData []byte
	pkData, salt, PBES2HMACAlgorithm, PBES2EncryptionAlgorithm, err = pbDecrypt(pkinfo, bmpPassword)
	if err != nil {
		err = errors.New("pkcs12: error decrypting PKCS#8 shrouded key bag: " + err.Error())
		return
	}

	ret := new(asn1.RawValue)
	if err = unmarshal(pkData, ret); err != nil {
		err = errors.New("pkcs12: error unmarshaling decrypted private key: " + err.Error())
		return
	}

	if privateKey, err = x509.ParsePKCS8PrivateKey(pkData); err != nil {
		err = errors.New("pkcs12: error parsing PKCS#8 private key: " + err.Error())
		return
	}

	algorithm = pkinfo.AlgorithmIdentifier.Algorithm
	return
}

func EncodePkcs8ShroudedKeyBagWithPassword(rand io.Reader, privateKey interface{}, password []rune,
	algorithm, pbes2Hash, pbes2Enc asn1.ObjectIdentifier, iterations uint, salt []byte) (asn1Data []byte, err error) {
	var encodedPassword []byte
	encodedPassword, err = bmpSliceZeroTerminated(password)
	if err != nil {
		return
	}
	defer func() {
		for i, _ := range encodedPassword {
			encodedPassword[i] = 0
		}
	}()
	return encodePkcs8ShroudedKeyBag(rand, privateKey, encodedPassword, algorithm, pbes2Hash, pbes2Enc, iterations, salt)
}

func encodePkcs8ShroudedKeyBag(rand io.Reader, privateKey interface{}, password []byte, algorithm, pbes2Hash, pbes2Enc asn1.ObjectIdentifier,
	iterations uint, randomSalt []byte) (asn1Data []byte, err error) {

	var pkData []byte
	if pkData, err = x509.MarshalPKCS8PrivateKey(privateKey); err != nil {
		return nil, errors.New("pkcs12: error encoding PKCS#8 private key: " + err.Error())
	}

	var paramBytes []byte
	if algorithm.Equal(OidPBES2) {
		if paramBytes, err = makePBES2Parameters(rand, pbes2Hash, pbes2Enc, randomSalt, int(iterations)); err != nil {
			return nil, errors.New("pkcs12: error encoding params: " + err.Error())
		}
	} else {
		if paramBytes, err = asn1.Marshal(pbeParams{Salt: randomSalt, Iterations: int(iterations)}); err != nil {
			return nil, errors.New("pkcs12: error encoding params: " + err.Error())
		}
	}

	var pkinfo encryptedPrivateKeyInfo
	pkinfo.AlgorithmIdentifier.Algorithm = algorithm
	pkinfo.AlgorithmIdentifier.Parameters.FullBytes = paramBytes

	if err = pbEncrypt(&pkinfo, pkData, password); err != nil {
		return nil, errors.New("pkcs12: error encrypting PKCS#8 shrouded key bag: " + err.Error())
	}

	if asn1Data, err = asn1.Marshal(pkinfo); err != nil {
		return nil, errors.New("pkcs12: error encoding PKCS#8 shrouded key bag: " + err.Error())
	}

	return asn1Data, nil
}

func decodeCertBag(asn1Data []byte) (x509Certificates []byte, err error) {
	bag := new(certBag)
	if err := unmarshal(asn1Data, bag); err != nil {
		return nil, errors.New("pkcs12: error decoding cert bag: " + err.Error())
	}
	if !bag.Id.Equal(oidCertTypeX509Certificate) {
		return nil, NotImplementedError("only X509 certificates are supported")
	}
	return bag.Data, nil
}

func encodeCertBag(x509Certificates []byte) (asn1Data []byte, err error) {
	var bag certBag
	bag.Id = oidCertTypeX509Certificate
	bag.Data = x509Certificates
	if asn1Data, err = asn1.Marshal(bag); err != nil {
		return nil, errors.New("pkcs12: error encoding cert bag: " + err.Error())
	}
	return asn1Data, nil
}
