// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkcs12 implements some of PKCS#12 (also known as P12 or PFX).  It is
// intended for decoding DER-encoded P12/PFX files for use with the crypto/tls
// package, and for encoding P12/PFX files for use by legacy applications which
// do not support newer formats.  Since PKCS#12 uses weak encryption
// primitives, it SHOULD NOT be used for new applications.
//
// Note that only DER-encoded PKCS#12 files are supported, even though PKCS#12
// allows BER encoding.  This is because encoding/asn1 only supports DER.
//
// This package is forked from golang.org/x/crypto/pkcs12, which is frozen.
// The implementation is distilled from https://tools.ietf.org/html/rfc7292
// and referenced documents.
//
// By definition, the Fingerprint is a hash of the public key bytes, hence one
// can use the Fingerprint returned from reading a p12 file to match the key
// with the certificate, as they will have the same hash.  This is important as
// when a p12 file is loaded, it may have multiple keys and certificates, which
// can be provided in any order.
//
// Before loading the proper cert with key to make a tls.Certificate, it is a good
// idea to do something like the following:
//
//	ce := p12.CertEntries[0]  // After we have determined this is the needed cert
//	for _, k := range p12.KeyEntries {
//	  if bytes.Match(k.Fingerprint, ce.Fingerprint) {
//	    t := tls.Certificate{
//	      Certificate: [][]byte{ce.Cert.Raw},
//	      Leaf:        ce.Cert,
//	      PrivateKey:  k.Key,
//	    }
//	  }
//	}
package pkcs12 // import "github.com/pschou/go-pkcs12"

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// DefaultPassword is the string "changeit", a commonly-used password for
// PKCS#12 files. Due to the weak encryption used by PKCS#12, it is
// RECOMMENDED that you use DefaultPassword when encoding PKCS#12 files,
// and protect the PKCS#12 files using other means.
const DefaultPassword = "changeit"

var (
	OidDataContentType          = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
	oidEncryptedDataContentType = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 6})

	oidFriendlyName     = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 20})
	oidLocalKeyID       = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 21})
	oidMicrosoftCSPName = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 17, 1})

	oidJavaTrustStore      = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 113894, 746875, 1, 1})
	oidAnyExtendedKeyUsage = asn1.ObjectIdentifier([]int{2, 5, 29, 37, 0})
)

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (i encryptedContentInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.ContentEncryptionAlgorithm
}

func (i encryptedContentInfo) Data() []byte { return i.EncryptedContent }

func (i *encryptedContentInfo) SetData(data []byte) { i.EncryptedContent = data }

type safeBag struct {
	Id         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

func (bag *safeBag) hasAttribute(id asn1.ObjectIdentifier) bool {
	for _, attr := range bag.Attributes {
		if attr.Id.Equal(id) {
			return true
		}
	}
	return false
}

func (bag *safeBag) getAttribute(id asn1.ObjectIdentifier) ([]byte, bool) {
	for _, attr := range bag.Attributes {
		if attr.Id.Equal(id) {
			return attr.Value.Bytes, true
		}
	}
	return nil, false
}

type pkcs12Attribute struct {
	Id    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type encryptedPrivateKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

func (i encryptedPrivateKeyInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.AlgorithmIdentifier
}

func (i encryptedPrivateKeyInfo) Data() []byte {
	return i.EncryptedData
}

func (i *encryptedPrivateKeyInfo) SetData(data []byte) {
	i.EncryptedData = data
}

// PEM block types
const (
	certificateType = "CERTIFICATE"
	privateKeyType  = "PRIVATE KEY"
)

// unmarshal calls asn1.Unmarshal, but also returns an error if there is any
// trailing data after unmarshaling.
func unmarshal(in []byte, out interface{}) error {
	trailing, err := asn1.Unmarshal(in, out)
	if err != nil {
		return err
	}
	if len(trailing) != 0 {
		return errors.New("pkcs12: trailing data found")
	}
	return nil
}

/*
// ToPEM converts all "safe bags" contained in pfxData to PEM blocks.
//
// Deprecated: ToPEM creates invalid PEM blocks (private keys
// are encoded as raw RSA or EC private keys rather than PKCS#8 despite being
// labeled "PRIVATE KEY").  To decode a PKCS#12 file, use [DecodeChain] instead,
// and use the [encoding/pem] package to convert to PEM if necessary.
func ToPEM(pfxData []byte, password []rune) ([]*pem.Block, error) {
	encodedPassword, err := bmpSliceZeroTerminated(password)
	if err != nil {
		return nil, ErrIncorrectPassword
	}
	defer func() {
		for i, _ := range encodedPassword {
			encodedPassword[i] = 0
		}
	}()

	bags, encodedPassword, _, _, _, _, err := getSafeContents(pfxData, encodedPassword)

	if err != nil {
		return nil, err
	}

	blocks := make([]*pem.Block, 0, len(bags))
	for _, bag := range bags {
		block, err := convertBag(&bag, encodedPassword)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}

	return blocks, nil
}

func convertBag(bag *safeBag, password []byte) (*pem.Block, error) {
	block := &pem.Block{
		Headers: make(map[string]string),
	}

	for _, attribute := range bag.Attributes {
		k, v, err := DecodeAttribute(&attribute)
		if err != nil {
			return nil, err
		}
		block.Headers[k] = v
	}

	switch {
	case bag.Id.Equal(oidCertBag):
		block.Type = certificateType
		certsData, err := decodeCertBag(bag.Value.Bytes)
		if err != nil {
			return nil, err
		}
		block.Bytes = certsData
	case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
		block.Type = privateKeyType

		key, _, salt, err := decodePkcs8ShroudedKeyBag(bag.Value.Bytes, password)
		if err != nil {
			return nil, err
		}

		switch key := key.(type) {
		case *rsa.PrivateKey:
			block.Bytes = x509.MarshalPKCS1PrivateKey(key)
		case *ecdsa.PrivateKey:
			block.Bytes, err = x509.MarshalECPrivateKey(key)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	default:
		return nil, errors.New("don't know how to convert a safe bag of type " + bag.Id.String())
	}
	return block, nil
}
*/

func DecodeAttribute(attribute *pkcs12Attribute) (key, value string, err error) {
	isString := false

	switch {
	case attribute.Id.Equal(oidFriendlyName):
		key = "friendlyName"
		isString = true
	case attribute.Id.Equal(oidLocalKeyID):
		key = "localKeyId"
	case attribute.Id.Equal(oidMicrosoftCSPName):
		// This key is chosen to match OpenSSL.
		key = "Microsoft CSP Name"
		isString = true
	default:
		return "", "", errors.New("pkcs12: unknown attribute with OID " + attribute.Id.String())
	}

	if isString {
		if err := unmarshal(attribute.Value.Bytes, &attribute.Value); err != nil {
			return "", "", err
		}
		if value, err = decodeBMPString(attribute.Value.Bytes); err != nil {
			return "", "", err
		}
	} else {
		var id []byte
		if err := unmarshal(attribute.Value.Bytes, &id); err != nil {
			return "", "", err
		}
		value = hex.EncodeToString(id)
	}

	return key, value, nil
}

/* DEPRECATED
// Decode extracts a certificate and private key from pfxData, which must be a DER-encoded PKCS#12 file. This function
// assumes that there is only one certificate and only one private key in the
// pfxData.  Since PKCS#12 files often contain more than one certificate, you
// probably want to use [DecodeChain] instead.
func Decode(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, err error) {
	var caCerts []*x509.Certificate
	privateKey, certificate, caCerts, err = DecodeChain(pfxData, password)
	if len(caCerts) != 0 {
		err = errors.New("pkcs12: expected exactly two safe bags in the PFX PDU")
	}
	return
}

// DecodeChain extracts a certificate, a CA certificate chain, and private key
// from pfxData, which must be a DER-encoded PKCS#12 file. This function
// assumes that there is at least one certificate and only one private key in
// the pfxData.  The first certificate is assumed to be the leaf certificate,
// and subsequent certificates, if any, are assumed to comprise the CA
// certificate chain.
func DecodeChain(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {
	p12 := P12{
		Password:         password,
		KeyBagAlgorithm:  OidPBEWithSHAAnd3KeyTripleDESCBC,
		CertBagAlgorithm: OidPBEWithSHAAnd40BitRC2CBC,
		MACAlgorithm:     OidSHA1,
		random:           rand.Reader,
	}
	err = Unmarshal(pfxData, &p12)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pkcs12: error decoding chain: %s", err)
	}
	if len(p12.KeyEntries) == 0 {
		return nil, nil, nil, errors.New("pkcs12: private key missing")
	}
	if len(p12.KeyEntries) != 1 {
		return nil, nil, nil, errors.New("pkcs12: expected exactly one key bag")
	}

	var CACerts []*x509.Certificate
	for _, c := range p12.CertEntries[1:] {
		CACerts = append(CACerts, c.Cert)
	}
	return p12.KeyEntries[0].Key, p12.CertEntries[0].Cert, CACerts, err
}
*/

// When doing key level custom encryption, one can provide a call back function
// to handle individual keys.  If no function is provided the settings
// Password, NoPassword, and KeyBagAlgorithm will be used for all the key
// bags.
type P12 struct {
	SkipDecodeErrors bool
	CertEntries      []CertEntry
	KeyEntries       []KeyEntry

	// Password based encryption settings
	Password []rune

	// These are defined when a password is provided, if left undefined defaults will be set
	MACAlgorithm                        asn1.ObjectIdentifier
	MACIterations, EncryptionIterations uint
	KeyBagAlgorithm, CertBagAlgorithm   asn1.ObjectIdentifier

	// When PBES2 is used
	PBES2_HMACAlgorithm, PBES2_EncryptionAlgorithm asn1.ObjectIdentifier

	random            io.Reader
	macSalt, safeSalt []byte

	// If unique passwords or algorithms must be assigned to each key, a custom callback may be defined
	CustomKeyEncrypt func(ke *KeyEntry) (encrypted []byte, isEncrypted bool, err error)
	CustomKeyDecrypt func(ke *KeyEntry, payload []byte) error
	CustomBagDecrypt func(info Decryptable, password []byte) (decrypted []byte, err error)
	CustomBagEncrypt func(info Encryptable, data []byte) error
}

type CertEntry struct {
	Cert         *x509.Certificate
	KeyID        []byte
	FriendlyName string
	Attributes   []pkcs12Attribute
}
type KeyEntry struct {
	Key          interface{}
	KeyID        []byte
	FriendlyName string
	Attributes   []pkcs12Attribute
	salt         []byte
}

// Set the random entropy source
func (p *P12) WithRand(r io.Reader) {
	p.random = r
}

// Generate salts
func (ts *TrustStore) GenerateSalts(sl int) (err error) {
	if ts.random == nil {
		ts.random = rand.Reader
	}
	if sl < 8 {
		sl = 8
	}
	ts.safeSalt = make([]byte, sl)
	if _, err = ts.random.Read(ts.safeSalt); err != nil {
		return
	}
	ts.macSalt = make([]byte, sl)
	if _, err = ts.random.Read(ts.macSalt); err != nil {
		return
	}
	return
}

// Generate salts
func (p *P12) GenerateSalts(sl int) (err error) {
	if p.random == nil {
		p.random = rand.Reader
	}
	if sl < 8 {
		sl = 8
	}
	p.safeSalt = make([]byte, sl)
	if _, err = p.random.Read(p.safeSalt); err != nil {
		return
	}
	p.macSalt = make([]byte, sl)
	if _, err = p.random.Read(p.macSalt); err != nil {
		return
	}
	for i := range p.KeyEntries {
		p.KeyEntries[i].salt = make([]byte, sl)
		if _, err = p.random.Read(p.KeyEntries[i].salt); err != nil {
			return
		}
	}
	return
}

func (d CertEntry) Clone() CertEntry {
	return CertEntry{
		Cert:         d.Cert,
		KeyID:        d.KeyID,
		FriendlyName: d.FriendlyName,
		Attributes:   append([]pkcs12Attribute{}, d.Attributes...),
	}
}

func (d KeyEntry) Clone() KeyEntry {
	return KeyEntry{
		Key:          d.Key,
		KeyID:        d.KeyID,
		FriendlyName: d.FriendlyName,
		Attributes:   append([]pkcs12Attribute{}, d.Attributes...),
	}
}

// Unmarshal extracts a certificate, a CA certificate chain, and private key from
// pfxData, which must be a DER-encoded PKCS#12 file. This function assumes
// that there is at least one certificate and only one private key in the
// pfxData.  The first certificate is assumed to be the leaf certificate, and
// subsequent certificates, if any, are assumed to comprise the CA certificate
// chain.
//
// Note:
//
//   - Password []byte is updated to show the password used in the file (if different
//     than given)
//
//   - The P12 output will be filled with the actual settings of the encryption
//     methods used in the PKCS#12
func Unmarshal(pfxData []byte, p12 *P12) (err error) {
	var encodedPassword []byte
	if len(p12.Password) > 0 {
		encodedPassword, err = bmpSliceZeroTerminated(p12.Password)
		if err != nil {
			return err
		}
		defer func() { // Zero out the memory
			for i, _ := range encodedPassword {
				encodedPassword[i] = 0
			}
		}()
	} else {
		encodedPassword = []byte{0, 0}
	}

	var bags []safeBag
	bags, encodedPassword, p12.MACAlgorithm, p12.MACIterations,
		p12.PBES2_HMACAlgorithm, p12.CertBagAlgorithm, p12.macSalt, err = getSafeContents(pfxData, encodedPassword, p12.CustomKeyDecrypt, p12.CustomBagDecrypt)
	if err != nil {
		return err
	}

	// Update the Password property
	if encodedPassword == nil {
		p12.Password = nil
	}

	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidCertBag):
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return err
			}
			certs, err := x509.ParseCertificates(certsData)
			if err != nil {
				return err
			}
			if len(certs) != 1 {
				err = errors.New("pkcs12: expected exactly one certificate in the certBag")
				return err
			}

			c := CertEntry{
				Cert:       certs[0],
				Attributes: bag.Attributes,
			}

			if friendlyName, ok := bag.getAttribute(oidFriendlyName); ok {
				var rawval asn1.RawValue

				if trailing, err := asn1.Unmarshal(friendlyName, &rawval); err == nil && len(trailing) == 0 {
					friendlyName = rawval.Bytes
				}

				fn, err := decodeBMPString(friendlyName)
				if err == nil {
					c.FriendlyName = fn
				}
			}

			if keyID, ok := bag.getAttribute(oidLocalKeyID); ok {
				c.KeyID = keyID
			} else if h, err := hashKey(certs[0].PublicKey); err == nil {
				c.KeyID = h
			} else {
				return fmt.Errorf("pkcs12: could not hash cert for fingerprint: %s", err)
			}
			p12.CertEntries = append(p12.CertEntries, c)

		case bag.Id.Equal(oidKeyBag):
			k := KeyEntry{
				Attributes: bag.Attributes,
			}

			if friendlyName, ok := bag.getAttribute(oidFriendlyName); ok {
				var rawval asn1.RawValue

				if trailing, err := asn1.Unmarshal(friendlyName, &rawval); err == nil && len(trailing) == 0 {
					friendlyName = rawval.Bytes
				}

				fn, err := decodeBMPString(friendlyName)
				if err == nil {
					k.FriendlyName = fn
				}
			}

			if keyID, ok := bag.getAttribute(oidLocalKeyID); ok {
				k.KeyID = keyID
			} else if h, err := hashKey(k.Key); err == nil {
				k.KeyID = h
			} else {
				return fmt.Errorf("pkcs12: could not hash key for fingerprint: %s", err)
			}

			if privateKey, err := x509.ParsePKCS8PrivateKey(bag.Value.Bytes); err != nil {
				return err
			} else {
				k.Key = privateKey
			}
			p12.KeyEntries = append(p12.KeyEntries, k)

		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):

			k := KeyEntry{
				Attributes: bag.Attributes,
			}

			if friendlyName, ok := bag.getAttribute(oidFriendlyName); ok {
				var rawval asn1.RawValue

				if trailing, err := asn1.Unmarshal(friendlyName, &rawval); err == nil && len(trailing) == 0 {
					friendlyName = rawval.Bytes
				}

				fn, err := decodeBMPString(friendlyName)
				if err == nil {
					k.FriendlyName = fn
				}
			}

			if keyID, ok := bag.getAttribute(oidLocalKeyID); ok {
				k.KeyID = keyID
			} else if h, err := hashKey(k.Key); err == nil {
				k.KeyID = h
			} else {
				return fmt.Errorf("pkcs12: could not hash key for fingerprint: %s", err)
			}

			if p12.CustomKeyDecrypt != nil {
				err = p12.CustomKeyDecrypt(&k, bag.Value.Bytes)
				if err != nil {
					return err
				}
				if k.Key == nil {
					continue
				}
			} else {
				k.Key, _, _, _, _, err = decodePkcs8ShroudedKeyBag(bag.Value.Bytes, encodedPassword)
				if err != nil {
					if p12.SkipDecodeErrors {
						continue
					}
					return err
				}
			}

			p12.KeyEntries = append(p12.KeyEntries, k)
		}
	}

	if len(p12.CertEntries) == 0 {
		return errors.New("pkcs12: certificate missing")
	}

	return nil
}

// TrustStore represents a Java TrustStore in P12 format.
type TrustStore struct {
	Entries []TrustStoreEntry

	Password                                       []rune
	MACAlgorithm                                   asn1.ObjectIdentifier
	MACIterations, EncryptionIterations            uint
	CertBagAlgorithm                               asn1.ObjectIdentifier
	PBES2_HMACAlgorithm, PBES2_EncryptionAlgorithm asn1.ObjectIdentifier
	random                                         io.Reader
	macSalt, safeSalt                              []byte

	// If unique passwords or algorithms must be assigned to each key, a custom callback may be defined
	CustomBagDecrypt func(info Decryptable, password []byte) (decrypted []byte, err error)
	CustomBagEncrypt func(info Encryptable, data []byte) error
}

// TrustStoreEntry represents an entry in a Java TrustStore.
type TrustStoreEntry struct {
	Cert         *x509.Certificate
	FriendlyName string
	Fingerprint  []byte
	KeyID        []byte
	Attributes   []pkcs12Attribute
}

func NewTrustStoreWithPassword(password []rune) *TrustStore {
	return &TrustStore{
		random:                    rand.Reader,
		Password:                  password,
		MACIterations:             1000,
		EncryptionIterations:      1000,
		MACAlgorithm:              OidSHA1,
		CertBagAlgorithm:          OidPBEWithSHAAnd40BitRC2CBC,
		PBES2_HMACAlgorithm:       nil,
		PBES2_EncryptionAlgorithm: nil,
	}
}

// Set the random entropy source
func (t *TrustStore) WithRand(r io.Reader) {
	t.random = r
}

/* DEPRECATED
// DecodeTrustStore extracts the certificates from pfxData, which must be a DER-encoded
// PKCS#12 file containing exclusively certificates with attribute 2.16.840.1.113894.746875.1.1,
// which is used by Java to designate a trust anchor.
func DecodeTrustStore(pfxData []byte, password string) (certs []*x509.Certificate, err error) {
	ts := TrustStore{
		Password:         password,
		CertBagAlgorithm: OidPBEWithSHAAnd40BitRC2CBC,
		MACAlgorithm:     OidSHA1,
	}
	err = UnmarshalTrustStore(pfxData, &ts)
	if err != nil {
		return
	}

	for _, e := range ts.Entries {
		certs = append(certs, e.Cert)
	}
	return
}
*/

// UnmarshalTrustStore extracts the TrustStoreEntries from pfxData, which must be a DER-encoded
// PKCS#12 file containing exclusively certificates with attribute 2.16.840.1.113894.746875.1.1,
// which is used by Java to designate a trust anchor.
func UnmarshalTrustStore(pfxData []byte, ts *TrustStore) (err error) {
	var encodedPassword []byte
	if len(ts.Password) > 0 {
		encodedPassword, err = bmpSliceZeroTerminated(ts.Password)
		if err != nil {
			return err
		}
	}

	var bags []safeBag
	bags, encodedPassword, ts.MACAlgorithm, ts.MACIterations, ts.PBES2_HMACAlgorithm, ts.CertBagAlgorithm, ts.macSalt,
		err = getSafeContents(pfxData, encodedPassword, nil, ts.CustomBagDecrypt)
	if err != nil {
		return err
	}

	for _, bag := range bags {
		switch {
		case bag.Id.Equal(oidCertBag):
			if !bag.hasAttribute(oidJavaTrustStore) {
				return errors.New("pkcs12: trust store contains a certificate that is not marked as trusted")
			}
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return err
			}
			parsedCerts, err := x509.ParseCertificates(certsData)
			if err != nil {
				return err
			}

			if len(parsedCerts) != 1 {
				err = errors.New("pkcs12: expected exactly one certificate in the certBag")
				return err
			}

			entry := TrustStoreEntry{
				Cert:       parsedCerts[0],
				Attributes: bag.Attributes,
			}

			entry.Fingerprint, err = hashKey(parsedCerts[0].PublicKey)
			if err != nil {
				return fmt.Errorf("pkcs12: could not hash cert for fingerprint: %s", err)
			}

			if friendlyName, ok := bag.getAttribute(oidFriendlyName); ok {
				var rawval asn1.RawValue

				if trailing, err := asn1.Unmarshal(friendlyName, &rawval); err == nil && len(trailing) == 0 {
					friendlyName = rawval.Bytes
				}

				fn, err := decodeBMPString(friendlyName)
				if err == nil {
					entry.FriendlyName = fn
				}
			}

			if keyID, ok := bag.getAttribute(oidLocalKeyID); ok {
				entry.KeyID = keyID
			}

			ts.Entries = append(ts.Entries, entry)

		default:
			return errors.New("pkcs12: expected only certificate bags")
		}
	}

	return
}

func getSafeContents(p12Data, password []byte,
	CustomKeyDecrypt func(*KeyEntry, []byte) error,
	CustomBagDecrypt func(info Decryptable, password []byte) (decrypted []byte, err error)) (bags []safeBag, updatedPassword []byte,
	macAlgorithm asn1.ObjectIdentifier, macIterations uint,
	HMACAlgorithm, EncryptionAlgorithm asn1.ObjectIdentifier, macSalt []byte, err error) {

	pfx := new(pfxPdu)
	if err = unmarshal(p12Data, pfx); err != nil {
		err = errors.New("pkcs12: error reading P12 data: " + err.Error())
		return
	}

	if pfx.Version != 3 {
		err = NotImplementedError("can only decode v3 PFX PDU's")
		return
	}

	if !pfx.AuthSafe.ContentType.Equal(OidDataContentType) {
		err = NotImplementedError("only password-protected PFX is implemented")
		return
	}

	// unmarshal the explicit bytes in the content for type 'data'
	if err = unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return
	}

	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		if len(password) != 0 && !(len(password) == 2 && password[0] == 0 && password[1] == 0) {
			err = errors.New("pkcs12: no MAC in data")
			return
		}
	} else if err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password); err != nil {
		if err == ErrIncorrectPassword && len(password) == 2 && password[0] == 0 && password[1] == 0 {
			// some implementations use an empty byte array
			// for the empty string password try one more
			// time with empty-empty password
			password = nil
			err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password)
		}
		if err != nil {
			return
		}
	}

	macAlgorithm = pfx.MacData.Mac.Algorithm.Algorithm
	macIterations = uint(pfx.MacData.Iterations)
	macSalt = pfx.MacData.MacSalt
	updatedPassword = password

	var authenticatedSafe []contentInfo
	if err = unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return
	}

	for _, ci := range authenticatedSafe {
		var data []byte

		switch {
		case ci.ContentType.Equal(OidDataContentType):
			if err = unmarshal(ci.Content.Bytes, &data); err != nil {
				return
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var encryptedData encryptedData
			if err = unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
				return
			}
			if encryptedData.Version != 0 {
				err = NotImplementedError("only version 0 of EncryptedData is supported")
				return
			}
			if CustomBagDecrypt != nil {
				if data, err = CustomBagDecrypt(encryptedData.EncryptedContentInfo, password); err != nil {
					return
				}
			} else {
				if data, _, HMACAlgorithm, EncryptionAlgorithm, err = pbDecrypt(encryptedData.EncryptedContentInfo, password); err != nil {
					return
				}
			}
		default:
			err = NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
			return
		}

		var safeContents []safeBag
		if err = unmarshal(data, &safeContents); err != nil {
			return
		}
		bags = append(bags, safeContents...)
	}

	return
}

// Create a new P12 with defaults
func New() *P12 {
	return &P12{
		KeyBagAlgorithm:      OidPBEWithSHAAnd3KeyTripleDESCBC,
		CertBagAlgorithm:     OidPBEWithSHAAnd40BitRC2CBC,
		MACAlgorithm:         OidSHA1,
		MACIterations:        2048,
		EncryptionIterations: 2048,
		random:               rand.Reader,
	}
}

// Create a new P12 with defaults and set the password
func NewWithPassword(password []rune) P12 {
	return P12{
		KeyBagAlgorithm:      OidPBEWithSHAAnd3KeyTripleDESCBC,
		CertBagAlgorithm:     OidPBEWithSHAAnd40BitRC2CBC,
		MACAlgorithm:         OidSHA1,
		random:               rand.Reader,
		MACIterations:        2048,
		EncryptionIterations: 2048,
		Password:             password,
	}
}

/*func (c *CertEntry) setFriendlyName(name string, err error) {
	bName, err := bmpString(name)
	if err != nil {
		return
	}
	var pkcs12Attributes []pkcs12Attribute
	var hasName bool
	// Loop over Attributes assigning the first friendlyName
	for _, attr := range c.Attributes {
		if attr.Id.Equal(oidFriendlyName) {
			if !hasName {
				attr.Value.Bytes = bName
				hasName = true
				pkcs12Attributes = append(pkcs12Attributes, attr)
			}
		} else {
			pkcs12Attributes = append(pkcs12Attributes, attr)
		}
	}

	// Append a friendlyName to the end if not set
	if !hasName {
		friendlyNameAttr := pkcs12Attribute{
			Id: oidFriendlyName,
			Value: asn1.RawValue{
				Class:      0,
				Tag:        17,
				IsCompound: true,
				Bytes:      bName,
			},
		}
		pkcs12Attributes = append(pkcs12Attributes, friendlyNameAttr)
	}
	c.Attributes = pkcs12Attributes
}

func (c *CertEntry) dedupAttributes() {
	var pkcs12Attributes []pkcs12Attribute
	// Make sure we don't have any duplicate attributes
builtAttributes:
	for _, attr := range c.Attributes {
		for _, dupAttr := range pkcs12Attributes {
			if attr.Id.Equal(dupAttr.Id) {
				continue builtAttributes
			}
		}
		pkcs12Attributes = append(pkcs12Attributes, attr)
	}
	c.Attributes = pkcs12Attributes
}

func (c *KeyEntry) SetFingerPrint() (err error) {
	h, err := hashKey(c.Key)
	if err != nil {
		return err
	}
	c.Fingerprint = h
	return nil
}

func (c *CertEntry) SetFingerPrint() (err error) {
	if c.Cert.PublicKey == nil {
		newCert, err := x509.ParseCertificate(c.Cert.Raw)
		if err != nil {
			return err
		}
		c.Cert = newCert
	}
	h, err := hashKey(c.Cert.PublicKey)
	if err != nil {
		return err
	}
	c.Fingerprint = h
	return nil
}

// Encode produces pfxData containing one private key (privateKey), an
// end-entity certificate (certificate), and any number of CA certificates
// (caCerts).
//
// The private key is encrypted with the provided password, but due to the
// weak encryption primitives used by PKCS#12, it is RECOMMENDED that you
// specify a hard-coded password (such as [DefaultPassword]) and protect
// the resulting pfxData using other means.
//
// The rand argument is used to provide entropy for the encryption, and
// can be set to [crypto/rand.Reader].
//
// Encode emulates the behavior of OpenSSL's PKCS12_create: it creates two
// SafeContents: one that's encrypted with RC2 (can be changed by altering
// Algorithms in the p12 struct) and contains the certificates, and another
// that is unencrypted and contains the private key shrouded with 3DES  The
// private key bag and the end-entity certificate bag have the LocalKeyId
// attribute set to the SHA-1 fingerprint of the end-entity certificate.
func Encode(rand io.Reader, privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, password string) (pfxData []byte, err error) {

	entries := []CertEntry{CertEntry{
		Cert: certificate,
	}}
	for _, c := range caCerts {
		entries = append(entries, CertEntry{Cert: c})
	}

	return Marshal(&P12{
		KeyEntries: []KeyEntry{KeyEntry{
			Key: privateKey,
		}},
		KeyBagAlgorithm:  OidPBEWithSHAAnd3KeyTripleDESCBC,
		CertBagAlgorithm: OidPBEWithSHAAnd40BitRC2CBC,
		MACAlgorithm:     OidSHA256,
		random:           rand,
		Password:         password,
		CertEntries:      entries,
	})
}
*/

// Marshal produces pfxData containing private keys (PrivateKeys),
// an entity certificates (CertEntries), and any number of CA certificates
// included as CertEntries.
//
// The private key is encrypted with the provided password, but due to the
// weak encryption primitives used by PKCS#12, it is RECOMMENDED that you
// specify a hard-coded password (such as [DefaultPassword]) and protect
// the resulting pfxData using other means.
//
// The p12.Rand argument is used to provide entropy for the encryption, and
// can be set to [crypto/rand.Reader].
//
// Encode uses the P12 structure with all the Algorithm specifications for
// for securing the PFX.
//
// Example usage:
//
//	p := pkcs12.NewWithPassword("mypass")
//	p.KeyEntries = append(p.KeyEntries, pkcs12.KeyEntry{Key: myKey})
//	p.CertEntries = append(p.CertEntries, pkcs12.CertEntry{Certificate: myCert})
//	derBytes, err := pkcs12.Marshal(p12)
//
// Example definition of a P12 with custom algorithms:
//
//	p := &pkcs12.P12{
//	  Password:         "myPassword",
//	  KeyBagAlgorithm:  pkcs12.OidPBEWithSHAAnd3KeyTripleDESCBC,
//	  CertBagAlgorithm: pkcs12.OidPBEWithSHAAnd40BitRC2CBC,
//	  MACAlgorithm:     pkcs12.OidSHA256,
//	})
func Marshal(p12 *P12) (pfxData []byte, err error) {
	var encodedPassword []byte
	if p12.MACAlgorithm == nil || p12.CertBagAlgorithm == nil || p12.MACIterations == 0 || p12.EncryptionIterations == 0 {
		if p12.MACIterations > 0 || p12.EncryptionIterations > 0 || p12.MACAlgorithm != nil || p12.CertBagAlgorithm != nil {
			err = errors.New("Cannot marshal P12 with password based encryption.  MACAlgorithm & CertBagAlgorithm must be set and MACIterations & EncryptionIterations must be greater than 0")
			return
		}
	} else {
		// Password based encryption enabled
		encodedPassword, err = bmpSliceZeroTerminated(p12.Password)
		if err != nil {
			return nil, err
		}
	}

	for i, c := range p12.CertEntries {
		if err := checkCert(fmt.Sprintf("CA certificate #%d", i), c.Cert); err != nil {
			return pfxData, err
		}
	}

	if p12.random == nil {
		// Make sure we have a sensible value if none is specified
		p12.random = rand.Reader
	}

	pfx := pfxPdu{
		Version: 3,
	}

	var certBags []safeBag
	for _, ce := range p12.CertEntries {
		certBag, err := makeCertBag(ce.Cert.Raw)
		if err != nil {
			return nil, err
		}
		certBag.Attributes = ce.Attributes
		setKeyID(certBag, ce.Cert)
		setFriendlyName(certBag, ce.FriendlyName)

		certBags = append(certBags, *certBag)
	}

	var keyBags []safeBag
	for _, k := range p12.KeyEntries {
		keyBag := &safeBag{
			Value: asn1.RawValue{
				Class:      2,
				Tag:        0,
				IsCompound: true,
			}}
		keyBag.Attributes = k.Attributes
		setKeyID(keyBag, k.Key)
		setFriendlyName(keyBag, k.FriendlyName)

		if p12.CustomKeyEncrypt != nil {
			// Call a custom algorithm if specified
			var encrypted bool
			keyBag.Value.Bytes, encrypted, err = p12.CustomKeyEncrypt(&k)
			if err != nil {
				return nil, err
			}
			if encrypted {
				keyBag.Id = oidPKCS8ShroundedKeyBag
			} else {
				keyBag.Id = oidKeyBag
			}
			if len(keyBag.Value.Bytes) == 0 {
				// Skip trying to decode this key
				continue
			}
		} else {
			// Otherwise use the built-in
			if p12.KeyBagAlgorithm == nil {
				keyBag.Id = oidKeyBag
				if keyBag.Value.Bytes, err = x509.MarshalPKCS8PrivateKey(k.Key); err != nil {
					return nil, err
				}
			} else {
				keyBag.Id = oidPKCS8ShroundedKeyBag
				if len(k.salt) == 0 {
					k.salt = make([]byte, 16)
					if _, err = rand.Read(k.salt); err != nil {
						return nil, errors.New("pkcs12: error reading random salt: " + err.Error())
					}
				}

				if keyBag.Value.Bytes, err = encodePkcs8ShroudedKeyBag(p12.random, k.Key,
					encodedPassword, p12.KeyBagAlgorithm, p12.PBES2_HMACAlgorithm, p12.PBES2_EncryptionAlgorithm, p12.EncryptionIterations, k.salt); err != nil {
					return nil, err
				}
			}
		}

		//, err := localKeyID(k.Key)
		if err != nil {
			return nil, err
		}

		//keyBag.Attributes = append(keyBag.Attributes, pkcs12Attributes...)
		keyBags = append(keyBags, *keyBag)
	}

	// Construct an authenticated safe with two SafeContents.
	// The first SafeContents is encrypted and contains the cert bags.
	// The second SafeContents is unencrypted and contains the shrouded key bag.
	var authenticatedSafe [2]contentInfo

	if len(p12.safeSalt) == 0 {
		p12.safeSalt = make([]byte, 8)
		if _, err = p12.random.Read(p12.safeSalt); err != nil {
			return nil, err
		}
	}

	if authenticatedSafe[0], err = makeSafeContents(p12.random, p12.CertBagAlgorithm, p12.PBES2_HMACAlgorithm, p12.PBES2_EncryptionAlgorithm,
		certBags, encodedPassword, p12.safeSalt,
		int(p12.EncryptionIterations), p12.CustomBagEncrypt); err != nil {
		return nil, err
	}
	if authenticatedSafe[1], err = makeSafeContents(p12.random, nil, nil, nil, keyBags, nil, nil, 0, nil); err != nil {
		return nil, err
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	if p12.MACAlgorithm != nil {
		// compute the MAC
		pfx.MacData.Mac.Algorithm.Algorithm = p12.MACAlgorithm
		if len(p12.macSalt) == 0 {
			p12.macSalt = make([]byte, 8)
			if _, err = p12.random.Read(p12.safeSalt); err != nil {
				return nil, err
			}
		}
		pfx.MacData.MacSalt = p12.macSalt
		if p12.MACIterations == 0 {
			p12.MACIterations = 1
		}
		pfx.MacData.Iterations = int(p12.MACIterations)
		if err = computeMac(&pfx.MacData, authenticatedSafeBytes, encodedPassword); err != nil {
			return nil, err
		}
	}

	pfx.AuthSafe.ContentType = OidDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		return nil, err
	}

	if pfxData, err = asn1.Marshal(pfx); err != nil {
		return nil, errors.New("pkcs12: error writing P12 data: " + err.Error())
	}
	return
}

/* DEPRECATED
// EncodeTrustStore produces pfxData containing any number of CA certificates
// (certs) to be trusted. The certificates will be marked with a special OID that
// allow it to be used as a Java TrustStore in Java 1.8 and newer.
//
// Due to the weak encryption primitives used by PKCS#12, it is RECOMMENDED that
// you specify a hard-coded password (such as [DefaultPassword]) and protect
// the resulting pfxData using other means.
//
// The rand argument is used to provide entropy for the encryption, and
// can be set to [crypto/rand.Reader].
//
// EncodeTrustStore creates a single SafeContents that's encrypted with RC2
// and contains the certificates.
//
// The Subject of the certificates are used as the Friendly Names (Aliases)
// within the resulting pfxData. If certificates share a Subject, then the
// resulting Friendly Names (Aliases) will be identical, which Java may treat as
// the same entry when used as a Java TrustStore, e.g. with `keytool`.  To
// customize the Friendly Names, use [EncodeTrustStoreEntries].
func EncodeTrustStore(rand io.Reader, certs []*x509.Certificate, password string) (pfxData []byte, err error) {
	var certsWithFriendlyNames []TrustStoreEntry
	for _, cert := range certs {
		certsWithFriendlyNames = append(certsWithFriendlyNames, TrustStoreEntry{
			Cert:         cert,
			FriendlyName: cert.Subject.String(),
		})
	}
	return EncodeTrustStoreEntries(rand, certsWithFriendlyNames, password)
}

// EncodeTrustStoreEntries produces pfxData containing any number of CA
// certificates (entries) to be trusted. The certificates will be marked with a
// special OID that allow it to be used as a Java TrustStore in Java 1.8 and newer.
//
// This is identical to [EncodeTrustStore], but also allows for setting specific
// Friendly Names (Aliases) to be used per certificate, by specifying a slice
// of TrustStoreEntry.
//
// If the same Friendly Name is used for more than one certificate, then the
// resulting Friendly Names (Aliases) in the pfxData will be identical, which Java
// may treat as the same entry when used as a Java TrustStore, e.g. with `keytool`.
//
// Due to the weak encryption primitives used by PKCS#12, it is RECOMMENDED that
// you specify a hard-coded password (such as [DefaultPassword]) and protect
// the resulting pfxData using other means.
//
// The rand argument is used to provide entropy for the encryption, and
// can be set to [crypto/rand.Reader].
//
// EncodeTrustStoreEntries creates a single SafeContents that's encrypted
// with RC2 and contains the certificates.
func EncodeTrustStoreEntries(rand io.Reader, entries []TrustStoreEntry, password string) (pfxData []byte, err error) {
	return MarshalTrustStore(&TrustStore{
		Entries:          entries,
		random:           rand,
		Password:         password,
		CertBagAlgorithm: OidPBEWithSHAAnd40BitRC2CBC,
		MACAlgorithm:     OidSHA1,
	})
}
*/

// MarshalTrustStore produces pfxData containing any number of CA certificates
// (entries) to be trusted. The certificates will be marked with a special OID
// that allow it to be used as a Java TrustStore in Java 1.8 and newer.
//
// This is identical to [EncodeTrustStore], but also allows for setting specific
// Friendly Names (Aliases) to be used per certificate, by specifying a slice
// of TrustStoreEntry and Algorithm for key/cert storage.
//
// If the same Friendly Name is used for more than one certificate, then the
// resulting Friendly Names (Aliases) in the pfxData will be identical, which Java
// may treat as the same entry when used as a Java TrustStore, e.g. with `keytool`.
//
// Due to the weak encryption primitives used by PKCS#12, it is RECOMMENDED that
// you specify a hard-coded password (such as [DefaultPassword]) and protect
// the resulting pfxData using other means.
//
// The rand argument is used to provide entropy for the encryption, and
// can be set to [crypto/rand.Reader].
//
// Example definition of a TrustStore:
//
//	ts := &pkcs12.TrustStore{
//	  Password:         []byte("myPassword"),
//	  CertBagAlgorithm: pkcs12.OidPBEWithSHAAnd40BitRC2CBC,
//	  MACAlgorithm:     pkcs12.OidSHA1,
//	})
//
// MarshalTrustStore takes a TrustStore structure with Algorithm specifications
// to use for for securing the PFX.
func MarshalTrustStore(ts *TrustStore) (pfxData []byte, err error) {
	var encodedPassword []byte
	if ts.MACAlgorithm == nil || ts.CertBagAlgorithm == nil || ts.MACIterations == 0 || ts.EncryptionIterations == 0 {
		if ts.MACIterations > 0 || ts.EncryptionIterations > 0 || ts.MACAlgorithm != nil || ts.CertBagAlgorithm != nil {
			err = errors.New("Cannot marshal with password based encryption.  MACAlgorithm & CertBagAlgorithm must be set and MACIterations & EncryptionIterations must be greater than 0")
			return
		}
	} else {
		// Password based encryption enabled
		encodedPassword, err = bmpSliceZeroTerminated(ts.Password)
		if err != nil {
			return nil, err
		}
	}

	// Quick sanity check on the certificates
	for i, c := range ts.Entries {
		if err := checkCert(fmt.Sprintf("TrustStoreEntry #%d", i), c.Cert); err != nil {
			return pfxData, err
		}
	}

	if ts.random == nil {
		// Make sure we have a sensible value if none is specified
		ts.random = rand.Reader
	}

	pfx := pfxPdu{
		Version: 3,
	}

	var certBags []safeBag
	for _, entry := range ts.Entries {

		certBag, err := makeCertBag(entry.Cert.Raw)
		if err != nil {
			return nil, err
		}

		certBag.Attributes = entry.Attributes
		setKeyID(certBag, entry.Cert)
		setFriendlyName(certBag, entry.FriendlyName)
		setJavaTrustStore(certBag)

		certBags = append(certBags, *certBag)
	}

	// Construct an authenticated safe with one SafeContent.
	// The SafeContents is encrypted and contains the cert bags.
	var authenticatedSafe [1]contentInfo
	if ts.EncryptionIterations == 0 {
		ts.EncryptionIterations = 1
	}
	if authenticatedSafe[0], err = makeSafeContents(ts.random, ts.CertBagAlgorithm, ts.PBES2_HMACAlgorithm, ts.PBES2_EncryptionAlgorithm,
		certBags, encodedPassword, ts.safeSalt, int(ts.EncryptionIterations), ts.CustomBagEncrypt); err != nil {
		return nil, err
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	if ts.MACAlgorithm != nil {
		// compute the MAC
		pfx.MacData.Mac.Algorithm.Algorithm = ts.MACAlgorithm
		if len(ts.macSalt) == 0 {
			ts.macSalt = make([]byte, 8)
		}
		pfx.MacData.MacSalt = ts.macSalt
		if _, err = rand.Read(pfx.MacData.MacSalt); err != nil {
			return nil, err
		}
		if ts.MACIterations == 0 {
			ts.MACIterations = 1
		}
		if ts.EncryptionIterations == 0 {
			ts.EncryptionIterations = 1
		}
		pfx.MacData.Iterations = int(ts.MACIterations)
		if err = computeMac(&pfx.MacData, authenticatedSafeBytes, encodedPassword); err != nil {
			return nil, err
		}
	}

	pfx.AuthSafe.ContentType = OidDataContentType
	pfx.AuthSafe.Content.Class = 2
	pfx.AuthSafe.Content.Tag = 0
	pfx.AuthSafe.Content.IsCompound = true
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafeBytes); err != nil {
		return nil, err
	}

	if pfxData, err = asn1.Marshal(pfx); err != nil {
		return nil, errors.New("pkcs12: error writing TrustStore data: " + err.Error())
	}
	return
}

func makeCertBag(certBytes []byte) (certBag *safeBag, err error) {
	certBag = new(safeBag)
	certBag.Id = oidCertBag
	certBag.Value.Class = 2
	certBag.Value.Tag = 0
	certBag.Value.IsCompound = true
	if certBag.Value.Bytes, err = encodeCertBag(certBytes); err != nil {
		return nil, err
	}
	return
}

func makeSafeContents(random io.Reader, algorithm, pbes2Hash, pbes2Enc asn1.ObjectIdentifier, bags []safeBag, password, salt []byte, iterations int,
	CustomBagEncrypt func(info Encryptable, data []byte) error) (ci contentInfo, err error) {

	var data []byte
	if data, err = asn1.Marshal(bags); err != nil {
		return
	}

	if algorithm == nil {
		ci.ContentType = OidDataContentType
		ci.Content.Class = 2
		ci.Content.Tag = 0
		ci.Content.IsCompound = true
		if ci.Content.Bytes, err = asn1.Marshal(data); err != nil {
			return
		}
	} else {
		var algo pkix.AlgorithmIdentifier
		algo.Algorithm = algorithm
		if algorithm.Equal(OidPBES2) {
			if algo.Parameters.FullBytes, err = MakePBES2Parameters(random, pbes2Hash, pbes2Enc, salt, iterations); err != nil {
				return
			}
		} else {
			if algo.Parameters.FullBytes, err = asn1.Marshal(pbeParams{Salt: salt, Iterations: iterations}); err != nil {
				return
			}
		}

		var encryptedData encryptedData
		encryptedData.Version = 0
		encryptedData.EncryptedContentInfo.ContentType = OidDataContentType
		encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm = algo
		if CustomBagEncrypt != nil {
			if err = CustomBagEncrypt(&encryptedData.EncryptedContentInfo, data); err != nil {
				return
			}
		} else {
			if err = pbEncrypt(&encryptedData.EncryptedContentInfo, data, password); err != nil {
				return
			}
		}

		ci.ContentType = oidEncryptedDataContentType
		ci.Content.Class = 2
		ci.Content.Tag = 0
		ci.Content.IsCompound = true
		if ci.Content.Bytes, err = asn1.Marshal(encryptedData); err != nil {
			return
		}
	}
	return
}

func setKeyID(bag *safeBag, key interface{}) error {
	Fingerprint, err := hashKey(key)
	if err != nil {
		return err
	}
	keyIDAttribute := pkcs12Attribute{
		Id: oidLocalKeyID,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        17,
			IsCompound: true,
		},
	}
	if keyIDAttribute.Value.Bytes, err = asn1.Marshal(Fingerprint[:]); err != nil {
		return err
	}
	attrs := []pkcs12Attribute{keyIDAttribute}
	for _, attr := range bag.Attributes {
		if !attr.Id.Equal(oidLocalKeyID) {
			attrs = append(attrs, attr)
		}
	}
	bag.Attributes = attrs
	return nil
}

func setFriendlyName(bag *safeBag, FriendlyName string) error {
	bmpFriendlyName, err := bmpString(FriendlyName)
	if err != nil {
		return err
	}

	encodedFriendlyName, err := asn1.Marshal(asn1.RawValue{
		Class:      0,
		Tag:        30,
		IsCompound: false,
		Bytes:      bmpFriendlyName,
	})

	if err != nil {
		return err
	}

	friendlyName := pkcs12Attribute{
		Id: oidFriendlyName,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        17,
			IsCompound: true,
			Bytes:      encodedFriendlyName,
		},
	}
	attrs := []pkcs12Attribute{friendlyName}
	for _, attr := range bag.Attributes {
		if !attr.Id.Equal(oidFriendlyName) {
			attrs = append(attrs, attr)
		}
	}
	bag.Attributes = attrs
	return nil
}

func setJavaTrustStore(bag *safeBag) error {
	extKeyUsageOidBytes, err := asn1.Marshal(oidAnyExtendedKeyUsage)
	if err != nil {
		return err
	}

	// the OidJavaTrustStore attribute contains the EKUs for which
	// this trust anchor will be valid
	javaTrustStoreAttribute := pkcs12Attribute{
		Id: oidJavaTrustStore,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        17,
			IsCompound: true,
			Bytes:      extKeyUsageOidBytes,
		},
	}

	attrs := []pkcs12Attribute{javaTrustStoreAttribute}
	for _, attr := range bag.Attributes {
		if !attr.Id.Equal(oidJavaTrustStore) {
			attrs = append(attrs, attr)
		}
	}
	bag.Attributes = attrs
	return nil
}
