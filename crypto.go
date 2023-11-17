// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"
	"io"

	gost256 "github.com/pedroalbanese/gogost/gost34112012256"
	gost512 "github.com/pedroalbanese/gogost/gost34112012512"
	"github.com/pschou/go-pkcs12/internal/rc2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

var (
	// Password based encryption
	OidPBES2  = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 5, 13})
	oidPBKDF2 = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 5, 12})

	// PBE algorithms
	OidPBEWithSHAAnd128BitRC4        = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 1})
	OidPBEWithSHAAnd40BitRC4         = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 2})
	OidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 3})
	OidPBEWithSHAAnd2KeyTripleDESCBC = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 4})
	OidPBEWithSHAAnd128BitRC2CBC     = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 5})
	OidPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 6})

	// PBES2 HMAC algorithms
	OidHmacWithGOST3411_256 = asn1.ObjectIdentifier([]int{1, 2, 643, 7, 1, 1, 4, 1})
	OidHmacWithGOST3411_512 = asn1.ObjectIdentifier([]int{1, 2, 643, 7, 1, 1, 4, 2})
	OidHmacWithMD5          = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 6})
	OidHmacWithSHA1         = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 7})
	OidHmacWithSHA256_224   = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 8})
	OidHmacWithSHA256       = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 9})
	OidHmacWithSHA512_384   = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 10})
	OidHmacWithSHA512       = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 11})
	OidHmacWithSHA512_224   = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 12})
	OidHmacWithSHA512_256   = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 13})
	OidHmacWithSHA3_224     = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 13})
	OidHmacWithSHA3_256     = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 14})
	OidHmacWithSHA3_384     = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 15})
	OidHmacWithSHA3_512     = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 16})

	// PBES2 Stream ciphers
	OidAES128CBC = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 1, 2})
	OidAES192CBC = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 1, 22})
	OidAES256CBC = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 1, 42})
)

var PBE_Algorithms_Available = map[string]asn1.ObjectIdentifier{
	"PBEWithSHAAnd128BitRC4":        OidPBEWithSHAAnd128BitRC4,
	"PBEWithSHAAnd40BitRC4":         OidPBEWithSHAAnd40BitRC4,
	"PBEWithSHAAnd3KeyTripleDESCBC": OidPBEWithSHAAnd3KeyTripleDESCBC,
	"PBEWithSHAAnd2KeyTripleDESCBC": OidPBEWithSHAAnd2KeyTripleDESCBC,
	"PBEWithSHAAnd128BitRC2CBC":     OidPBEWithSHAAnd128BitRC2CBC,
	"PBEWithSHAAnd40BitRC2CBC":      OidPBEWithSHAAnd40BitRC2CBC,
	"PBES2":                         OidPBES2,
}

var PBES2_Ciphers_Available = map[string]asn1.ObjectIdentifier{
	"AES128CBC": OidAES128CBC,
	"AES192CBC": OidAES192CBC,
	"AES256CBC": OidAES256CBC,
}

var PBES2_HMACs_Available = map[string]asn1.ObjectIdentifier{
	"GOST3411_256": OidHmacWithGOST3411_256,
	"GOST3411_512": OidHmacWithGOST3411_512,
	"MD5":          OidHmacWithMD5,
	"SHA1":         OidHmacWithSHA1,
	"SHA256_224":   OidHmacWithSHA256_224,
	"SHA256":       OidHmacWithSHA256,
	"SHA512_384":   OidHmacWithSHA512_384,
	"SHA512":       OidHmacWithSHA512,
	"SHA512_224":   OidHmacWithSHA512_224,
	"SHA512_256":   OidHmacWithSHA512_256,
	"SHA3_224":     OidHmacWithSHA3_224,
	"SHA3_256":     OidHmacWithSHA3_256,
	"SHA3_384":     OidHmacWithSHA3_384,
	"SHA3_512":     OidHmacWithSHA3_512,
}

// pbeCipher is an abstraction of a PKCS#12 cipher.
type pbeCipher interface {
	// create returns a cipher.Block given a key.
	create(key []byte) (cipher.Block, error)
	// deriveKey returns a key derived from the given password and salt.
	deriveKey(salt, password []byte, iterations int) []byte
	// deriveKey returns an IV derived from the given password and salt.
	deriveIV(salt, password []byte, iterations int) []byte
}

type shaWith2KeyTripleDESCBC struct{}

func (shaWith2KeyTripleDESCBC) create(key []byte) (cipher.Block, error) {
	return des.NewTripleDESCipher(key)
}

func (shaWith2KeyTripleDESCBC) deriveKey(salt, password []byte, iterations int) []byte {
	key := pbkdf(sha1.New, 20, 64, salt, password, iterations, 1, 16)
	return append(key, key[:8]...)
}

func (shaWith2KeyTripleDESCBC) deriveIV(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1.New, 20, 64, salt, password, iterations, 2, 8)
}

type shaWith3KeyTripleDESCBC struct{}

func (shaWith3KeyTripleDESCBC) create(key []byte) (cipher.Block, error) {
	return des.NewTripleDESCipher(key)
}

func (shaWith3KeyTripleDESCBC) deriveKey(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1.New, 20, 64, salt, password, iterations, 1, 24)
}

func (shaWith3KeyTripleDESCBC) deriveIV(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1.New, 20, 64, salt, password, iterations, 2, 8)
}

type shaWith40BitRC4 struct{}

func (shaWith40BitRC4) create(key []byte) (cipher.Block, error) {
	stream, err := rc4.NewCipher(key)
	return streamToBlock{stream}, err
}

func (shaWith40BitRC4) deriveKey(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1.New, 20, 64, salt, password, iterations, 1, 5)
}

func (shaWith40BitRC4) deriveIV(salt, password []byte, iterations int) []byte {
	return []byte{0}
}

type shaWith128BitRC4 struct{}

func (shaWith128BitRC4) create(key []byte) (cipher.Block, error) {
	stream, err := rc4.NewCipher(key)
	return streamToBlock{stream}, err
}

func (shaWith128BitRC4) deriveKey(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1.New, 20, 64, salt, password, iterations, 1, 16)
}

func (shaWith128BitRC4) deriveIV(salt, password []byte, iterations int) []byte {
	return []byte{0}
}

type shaWith40BitRC2CBC struct{}

func (shaWith40BitRC2CBC) create(key []byte) (cipher.Block, error) {
	return rc2.New(key, len(key)*8)
}

func (shaWith40BitRC2CBC) deriveKey(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1.New, 20, 64, salt, password, iterations, 1, 5)
}

func (shaWith40BitRC2CBC) deriveIV(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1.New, 20, 64, salt, password, iterations, 2, 8)
}

type shaWith128BitRC2CBC struct{}

func (shaWith128BitRC2CBC) create(key []byte) (cipher.Block, error) {
	return rc2.New(key, len(key)*8)
}

func (shaWith128BitRC2CBC) deriveKey(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1.New, 20, 64, salt, password, iterations, 1, 16)
}

func (shaWith128BitRC2CBC) deriveIV(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1.New, 20, 64, salt, password, iterations, 2, 8)
}

type pbeParams struct {
	Salt       []byte
	Iterations int
}

func pbeCipherFor(algorithm pkix.AlgorithmIdentifier, password []byte) (block cipher.Block, iv, salt []byte, HMACAlgorithm, EncryptionAlgorithm asn1.ObjectIdentifier, err error) {
	var cipherType pbeCipher

	switch {
	case algorithm.Algorithm.Equal(OidPBEWithSHAAnd3KeyTripleDESCBC):
		cipherType = shaWith3KeyTripleDESCBC{}
	case algorithm.Algorithm.Equal(OidPBEWithSHAAnd2KeyTripleDESCBC):
		cipherType = shaWith2KeyTripleDESCBC{}
	case algorithm.Algorithm.Equal(OidPBEWithSHAAnd40BitRC2CBC):
		cipherType = shaWith40BitRC2CBC{}
	case algorithm.Algorithm.Equal(OidPBEWithSHAAnd128BitRC2CBC):
		cipherType = shaWith128BitRC2CBC{}
	case algorithm.Algorithm.Equal(OidPBEWithSHAAnd40BitRC4):
		cipherType = shaWith40BitRC4{}
	case algorithm.Algorithm.Equal(OidPBEWithSHAAnd128BitRC4):
		cipherType = shaWith128BitRC4{}
	case algorithm.Algorithm.Equal(OidPBES2):
		// rfc7292#appendix-B.1 (the original PKCS#12 PBE) requires passwords formatted as BMPStrings.
		// However, rfc8018#section-3 recommends that the password for PBES2 follow ASCII or UTF-8.
		// This is also what Windows expects.
		// Therefore, we convert the password to UTF-8.
		var utf8Password []byte
		defer func() {
			for i := range utf8Password {
				utf8Password[i] = 0
			}
		}()

		utf8Password, err = decodeBMPSlice(password)
		if err != nil {
			return
		}
		return pbes2CipherFor(algorithm, utf8Password)
	case algorithm.Algorithm.Equal(OidDataContentType):
		// When there is no encryption
		return
	default:
		err = NotImplementedError("algorithm " + algorithm.Algorithm.String() + " is not supported")
		return
	}

	var params pbeParams
	if err = unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return
	}

	key := cipherType.deriveKey(params.Salt, password, params.Iterations)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	block, err = cipherType.create(key)
	if err != nil {
		return
	}

	iv = cipherType.deriveIV(params.Salt, password, params.Iterations)
	salt = params.Salt
	return
}

func pbDecrypterFor(algorithm pkix.AlgorithmIdentifier, password []byte) (blockMode cipher.BlockMode, blockSize int,
	salt []byte, HMACAlgorithm, EncryptionAlgorithm asn1.ObjectIdentifier, err error) {
	var iv []byte
	var block cipher.Block
	block, iv, salt, HMACAlgorithm, EncryptionAlgorithm, err = pbeCipherFor(algorithm, password)
	if err != nil {
		return
	}

	if len(iv) == 1 {
		var ok bool
		if blockMode, ok = block.(cipher.BlockMode); ok {
			blockSize = 1
			return
		}
		err = errors.New("pkcs12: unexpected cipher block")
		return
	}

	if block == nil {
		blockMode, blockSize = noCipher{}, 1
		return
	}

	blockMode = cipher.NewCBCDecrypter(block, iv)
	blockSize = block.BlockSize()

	return
}

func BagDecrypt(info Decryptable, password []byte) (decrypted []byte, salt []byte, HMACAlgorithm, EncryptionAlgorithm asn1.ObjectIdentifier, err error) {
	return pbDecrypt(info, password)
}

func pbDecrypt(info Decryptable, password []byte) (decrypted []byte, salt []byte, HMACAlgorithm, EncryptionAlgorithm asn1.ObjectIdentifier, err error) {
	var cbc cipher.BlockMode
	var blockSize int
	cbc, blockSize, salt, HMACAlgorithm, EncryptionAlgorithm, err = pbDecrypterFor(info.Algorithm(), password)
	if err != nil {
		return
	}

	encrypted := info.Data()
	if len(encrypted) == 0 {
		err = errors.New("pkcs12: empty encrypted data")
		return
	}
	if len(encrypted)%blockSize != 0 {
		err = errors.New("pkcs12: input is not a multiple of the block size")
		return
	}
	decrypted = make([]byte, len(encrypted))
	cbc.CryptBlocks(decrypted, encrypted)

	psLen := int(decrypted[len(decrypted)-1])
	if psLen == 0 || psLen > blockSize {
		decrypted, err = nil, ErrDecryption
		return
	}

	if len(decrypted) < psLen {
		decrypted, err = nil, ErrDecryption
		return
	}

	ps := decrypted[len(decrypted)-psLen:]
	decrypted = decrypted[:len(decrypted)-psLen]
	if bytes.Compare(ps, bytes.Repeat([]byte{byte(psLen)}, psLen)) != 0 {
		decrypted, err = nil, ErrDecryption
		return
	}

	return
}

//	PBES2-params ::= SEQUENCE {
//		keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
//		encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
//	}
type pbes2Params struct {
	Kdf              pkix.AlgorithmIdentifier
	EncryptionScheme pkix.AlgorithmIdentifier
}

//	PBKDF2-params ::= SEQUENCE {
//	    salt CHOICE {
//	      specified OCTET STRING,
//	      otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
//	    },
//	    iterationCount INTEGER (1..MAX),
//	    keyLength INTEGER (1..MAX) OPTIONAL,
//	    prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
//	    algid-hmacWithSHA1
//	}
type pbkdf2Params struct {
	Salt       asn1.RawValue
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	Prf        pkix.AlgorithmIdentifier `asn1:"optional"`
}

func pbes2CipherFor(algorithm pkix.AlgorithmIdentifier, password []byte) (block cipher.Block, iv []byte,
	salt []byte, HMACAlgorithm, EncryptionAlgorithm asn1.ObjectIdentifier, err error) {
	var params pbes2Params
	if err = unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return
	}

	if !params.Kdf.Algorithm.Equal(oidPBKDF2) {
		err = NotImplementedError("kdf algorithm " + params.Kdf.Algorithm.String() + " is not supported")
		return
	}

	var kdfParams pbkdf2Params
	if err = unmarshal(params.Kdf.Parameters.FullBytes, &kdfParams); err != nil {
		return
	}
	if kdfParams.Salt.Tag != asn1.TagOctetString {
		err = errors.New("pkcs12: only octet string salts are supported for pbkdf2")
		return
	}

	var prf func() hash.Hash
	switch {
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithGOST3411_256):
		prf = gost256.New
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithGOST3411_512):
		prf = gost512.New
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithMD5):
		prf = md5.New
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithSHA1):
		prf = sha1.New
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithSHA256_224):
		prf = sha256.New224
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithSHA256):
		prf = sha256.New
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithSHA512_384):
		prf = sha512.New384
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithSHA512):
		prf = sha512.New
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithSHA512_224):
		prf = sha512.New512_224
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithSHA512_256):
		prf = sha512.New512_256
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithSHA3_224):
		prf = sha3.New224
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithSHA3_256):
		prf = sha3.New256
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithSHA3_384):
		prf = sha3.New384
	case kdfParams.Prf.Algorithm.Equal(OidHmacWithSHA3_512):
		prf = sha3.New512
	case kdfParams.Prf.Algorithm.Equal(asn1.ObjectIdentifier([]int{})):
		prf = sha1.New
	}

	iv = params.EncryptionScheme.Parameters.Bytes
	salt = kdfParams.Salt.Bytes
	HMACAlgorithm = kdfParams.Prf.Algorithm
	EncryptionAlgorithm = params.EncryptionScheme.Algorithm

	switch {
	case params.EncryptionScheme.Algorithm.Equal(OidAES128CBC):
		key := pbkdf2.Key(password, kdfParams.Salt.Bytes, kdfParams.Iterations, 16, prf)
		block, err = aes.NewCipher(key)
		if err != nil {
			return
		}
	case params.EncryptionScheme.Algorithm.Equal(OidAES192CBC):
		key := pbkdf2.Key(password, kdfParams.Salt.Bytes, kdfParams.Iterations, 24, prf)
		block, err = aes.NewCipher(key)
		if err != nil {
			return
		}
	case params.EncryptionScheme.Algorithm.Equal(OidAES256CBC):
		key := pbkdf2.Key(password, kdfParams.Salt.Bytes, kdfParams.Iterations, 32, prf)
		block, err = aes.NewCipher(key)
		if err != nil {
			return
		}
	default:
		err = NotImplementedError("pbes2 algorithm " + params.EncryptionScheme.Algorithm.String() + " is not supported")
	}
	return
}

// decryptable abstracts an object that contains ciphertext.
type Decryptable interface {
	Algorithm() pkix.AlgorithmIdentifier
	Data() []byte
}

func pbEncrypterFor(algorithm pkix.AlgorithmIdentifier, password []byte) (cipher.BlockMode, int, error) {
	block, iv, _, _, _, err := pbeCipherFor(algorithm, password)
	if err != nil {
		return nil, 0, err
	}

	if len(iv) == 1 {
		if bm, ok := block.(cipher.BlockMode); ok {
			return bm, 1, nil
		}
		return nil, 0, errors.New("pkcs12: unexpected cipher block")
	}

	if block == nil {
		return noCipher{}, 1, nil
	}

	return cipher.NewCBCEncrypter(block, iv), block.BlockSize(), nil
}

func BagEncrypt(info Encryptable, decrypted, password []byte) (err error) {
	return pbEncrypt(info, decrypted, password)
}

func pbEncrypt(info Encryptable, decrypted []byte, password []byte) error {
	cbc, blockSize, err := pbEncrypterFor(info.Algorithm(), password)
	if err != nil {
		return err
	}

	psLen := blockSize - len(decrypted)%blockSize
	encrypted := make([]byte, len(decrypted)+psLen)
	copy(encrypted[:len(decrypted)], decrypted)
	copy(encrypted[len(decrypted):], bytes.Repeat([]byte{byte(psLen)}, psLen))
	cbc.CryptBlocks(encrypted, encrypted)

	info.SetData(encrypted)

	return nil
}

// encryptable abstracts a object that contains ciphertext.
type Encryptable interface {
	Algorithm() pkix.AlgorithmIdentifier
	SetData([]byte)
}

func makePBES2Parameters(rand io.Reader, hmacAlgorithm, encryptionAlgorithm asn1.ObjectIdentifier, salt []byte, iterations int) ([]byte, error) {
	var err error

	randomIV := make([]byte, 16)
	if _, err := rand.Read(randomIV); err != nil {
		return nil, err
	}

	var kdfparams pbkdf2Params
	if kdfparams.Salt.FullBytes, err = asn1.Marshal(salt); err != nil {
		return nil, err
	}
	kdfparams.Iterations = iterations
	if hmacAlgorithm == nil {
		return nil, errors.New("PBES2 HMAC Algorithm must be specified")
	}
	kdfparams.Prf.Algorithm = hmacAlgorithm

	var params pbes2Params
	params.Kdf.Algorithm = oidPBKDF2
	if params.Kdf.Parameters.FullBytes, err = asn1.Marshal(kdfparams); err != nil {
		return nil, err
	}
	if encryptionAlgorithm == nil {
		return nil, errors.New("PBES2 Encryption Algorithm must be specified")
	}
	params.EncryptionScheme.Algorithm = encryptionAlgorithm
	if params.EncryptionScheme.Parameters.FullBytes, err = asn1.Marshal(randomIV); err != nil {
		return nil, err
	}

	return asn1.Marshal(params)
}
