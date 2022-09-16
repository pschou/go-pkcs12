// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkcs12 implements some of PKCS#12 (also known as P12 or PFX).
// It is intended for decoding DER-encoded P12/PFX files for use with the crypto/tls
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
package pkcs12 // import "software.sslmate.com/src/go-pkcs12"

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
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
	oidDataContentType          = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
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

// ToPEM converts all "safe bags" contained in pfxData to PEM blocks.
//
// Deprecated: ToPEM creates invalid PEM blocks (private keys
// are encoded as raw RSA or EC private keys rather than PKCS#8 despite being
// labeled "PRIVATE KEY").  To decode a PKCS#12 file, use [DecodeChain] instead,
// and use the [encoding/pem] package to convert to PEM if necessary.
func ToPEM(pfxData []byte, password string) ([]*pem.Block, error) {
	encodedPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, ErrIncorrectPassword
	}

	bags, encodedPassword, _, _, err := getSafeContents(pfxData, encodedPassword, 2)

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

		key, _, err := decodePkcs8ShroudedKeyBag(bag.Value.Bytes, password)
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
	conf := DefaultConfig.Clone()
	conf.Password = password
	conf.HasPassword = true
	p12 := P12{}
	err = Unmarshal(pfxData, &p12, conf)
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

type P12 struct {
	CertEntries                                     []CertEntry
	KeyEntries                                      []KeyEntry
	MACAlgorithm, CertBagAlgorithm, KeyBagAlgorithm asn1.ObjectIdentifier
	HasPassword                                     bool
}

type CertEntry struct {
	Cert        *x509.Certificate
	Fingerprint []byte
	Attributes  []pkcs12Attribute
}
type KeyEntry struct {
	Key         interface{}
	Fingerprint []byte
}

func (d CertEntry) Clone() CertEntry {
	return CertEntry{
		Cert:        d.Cert,
		Fingerprint: d.Fingerprint,
		Attributes:  append([]pkcs12Attribute{}, d.Attributes...),
	}
}

func (d KeyEntry) Clone() KeyEntry {
	return KeyEntry{
		Key:         d.Key,
		Fingerprint: d.Fingerprint,
	}
}

func (d P12) Clone() P12 {
	p12 := P12{
		MACAlgorithm:     d.MACAlgorithm,
		CertBagAlgorithm: d.CertBagAlgorithm,
		KeyBagAlgorithm:  d.KeyBagAlgorithm,
	}
	for _, e := range d.CertEntries {
		p12.CertEntries = append(p12.CertEntries, e.Clone())
	}
	for _, e := range d.KeyEntries {
		p12.KeyEntries = append(p12.KeyEntries, e.Clone())
	}
	return p12
}

// Decode extracts a certificate, a CA certificate chain, and private key from
// pfxData, which must be a DER-encoded PKCS#12 file. This function assumes
// that there is at least one certificate and only one private key in the
// pfxData.  The first certificate is assumed to be the leaf certificate, and
// subsequent certificates, if any, are assumed to comprise the CA certificate
// chain.
//
// Note:
//
// - HasPassword bool is updated to show if an empty string password was used
// or no password when an empty string is provided.
//
// - The P12 output will be filled with the actual settings of the encryption
// methods used in the PKCS#12
func Unmarshal(pfxData []byte, p12 *P12, config *Config) (err error) {
	var encodedPassword []byte
	if config.HasPassword {
		encodedPassword, err = bmpStringZeroTerminated(config.Password)
		if err != nil {
			return err
		}
	} else {
		encodedPassword, _ = bmpStringZeroTerminated("")
	}

	bags, encodedPassword, algorithm, macAlgorithm, err := getSafeContents(pfxData, encodedPassword, 2)
	if err != nil {
		return err
	}
	p12.CertBagAlgorithm = algorithm
	p12.MACAlgorithm = macAlgorithm

	// Update the HasPassword property
	p12.HasPassword = encodedPassword != nil

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
			if h, err := hashKey(certs[0].PublicKey); err == nil {
				c.Fingerprint = h
			} else {
				return fmt.Errorf("pkcs12: could not hash cert for fingerprint: %s", err)
			}
			p12.CertEntries = append(p12.CertEntries, c)

		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			PrivateKey, keyAlgorithm, err := decodePkcs8ShroudedKeyBag(bag.Value.Bytes, encodedPassword)
			if err != nil {
				if config.SkipDecodeErrors {
					continue
				}
				return err
			}
			p12.KeyBagAlgorithm = keyAlgorithm

			k := KeyEntry{Key: PrivateKey}
			if h, err := hashKey(PrivateKey); err == nil {
				k.Fingerprint = h
			} else {
				return fmt.Errorf("pkcs12: could not hash key for fingerprint: %s", err)
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
	Entries                        []TrustStoreEntry
	MACAlgorithm, CertBagAlgorithm asn1.ObjectIdentifier
	HasPassword                    bool
}

// DecodeTrustStore extracts the certificates from pfxData, which must be a DER-encoded
// PKCS#12 file containing exclusively certificates with attribute 2.16.840.1.113894.746875.1.1,
// which is used by Java to designate a trust anchor.
func DecodeTrustStore(pfxData []byte, password string) (certs []*x509.Certificate, err error) {
	conf := DefaultConfig.Clone()
	conf.Password = password
	conf.HasPassword = true
	ts := TrustStore{}
	err = DecodeTrustStoreWithConfig(pfxData, &ts, conf)
	if err != nil {
		return
	}

	for _, e := range ts.Entries {
		certs = append(certs, e.Cert)
	}
	return
}

// DecodeTrustStore extracts the TrustStoreEntries from pfxData, which must be a DER-encoded
// PKCS#12 file containing exclusively certificates with attribute 2.16.840.1.113894.746875.1.1,
// which is used by Java to designate a trust anchor.
func DecodeTrustStoreWithConfig(pfxData []byte, ts *TrustStore, config *Config) (err error) {
	var encodedPassword []byte
	if config.HasPassword {
		encodedPassword, err = bmpStringZeroTerminated(config.Password)
		if err != nil {
			return err
		}
	}

	bags, encodedPassword, algorithm, macAlgorithm, err := getSafeContents(pfxData, encodedPassword, 1)
	if err != nil {
		return err
	}
	ts.HasPassword = encodedPassword != nil
	ts.CertBagAlgorithm = algorithm
	ts.MACAlgorithm = macAlgorithm

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
				Cert: parsedCerts[0],
			}

			if friendlyName, ok := bag.getAttribute(oidFriendlyName); ok {
				fn, err := decodeBMPString(friendlyName)
				if err == nil {
					entry.FriendlyName = fn
				}
			}

			ts.Entries = append(ts.Entries, entry)

		default:
			return errors.New("pkcs12: expected only certificate bags")
		}
	}

	return
}

func getSafeContents(p12Data, password []byte, expectedItems int) (bags []safeBag, updatedPassword []byte,
	algorithm, macAlgorithm asn1.ObjectIdentifier, err error) {
	pfx := new(pfxPdu)
	if err := unmarshal(p12Data, pfx); err != nil {
		return nil, nil, nil, nil, errors.New("pkcs12: error reading P12 data: " + err.Error())
	}

	if pfx.Version != 3 {
		return nil, nil, nil, nil, NotImplementedError("can only decode v3 PFX PDU's")
	}

	if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil, nil, nil, nil, NotImplementedError("only password-protected PFX is implemented")
	}

	// unmarshal the explicit bytes in the content for type 'data'
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, nil, nil, nil, err
	}

	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		if !(len(password) == 2 && password[0] == 0 && password[1] == 0) {
			return nil, nil, nil, nil, errors.New("pkcs12: no MAC in data")
		}
	} else if err := verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password); err != nil {
		if err == ErrIncorrectPassword && len(password) == 2 && password[0] == 0 && password[1] == 0 {
			// some implementations use an empty byte array
			// for the empty string password try one more
			// time with empty-empty password
			password = nil
			err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password)
		}
		if err != nil {
			return nil, nil, nil, nil, err
		}
		macAlgorithm = pfx.MacData.Mac.Algorithm.Algorithm
	}

	var authenticatedSafe []contentInfo
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return nil, nil, nil, nil, err
	}

	if len(authenticatedSafe) != expectedItems {
		return nil, nil, nil, nil, NotImplementedError("expected exactly two items in the authenticated safe")
	}

	for _, ci := range authenticatedSafe {
		var data []byte

		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if err := unmarshal(ci.Content.Bytes, &data); err != nil {
				return nil, nil, nil, nil, err
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var encryptedData encryptedData
			if err := unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
				return nil, nil, nil, nil, err
			}
			if encryptedData.Version != 0 {
				return nil, nil, nil, nil, NotImplementedError("only version 0 of EncryptedData is supported")
			}
			if data, err = pbDecrypt(encryptedData.EncryptedContentInfo, password); err != nil {
				return nil, nil, nil, nil, err
			}
			algorithm = encryptedData.EncryptedContentInfo.Algorithm().Algorithm
		default:
			return nil, nil, nil, nil, NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
		}

		var safeContents []safeBag
		if err := unmarshal(data, &safeContents); err != nil {
			return nil, nil, nil, nil, err
		}
		bags = append(bags, safeContents...)
	}

	return bags, password, algorithm, macAlgorithm, nil
}

// Config defines the MAC and Cipher algorithms to use for writing out a
// PKCS#12 file.
type Config struct {
	HasPassword                                     bool
	Password                                        string
	MACAlgorithm, CertBagAlgorithm, KeyBagAlgorithm asn1.ObjectIdentifier
	Random                                          io.Reader
	SkipDecodeErrors                                bool
}

func (d Config) Clone() *Config {
	return &Config{
		HasPassword:      d.HasPassword,
		Password:         d.Password,
		MACAlgorithm:     d.MACAlgorithm,
		CertBagAlgorithm: d.CertBagAlgorithm,
		KeyBagAlgorithm:  d.KeyBagAlgorithm,
		Random:           d.Random,
		SkipDecodeErrors: d.SkipDecodeErrors,
	}
}

func (c *CertEntry) SetFriendlyName(name string, err error) {
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
	pkcs12Attributes, err := localKeyID(c.Cert.PublicKey)
	if err != nil {
		return err
	}
	c.Fingerprint = pkcs12Attributes[0].Value.Bytes

	// Loop over Attributes adding the entries
	for _, attr := range c.Attributes {
		if !attr.Id.Equal(oidLocalKeyID) {
			pkcs12Attributes = append(pkcs12Attributes, attr)
		}
	}
	c.Attributes = pkcs12Attributes
	return nil
}

var DefaultConfig = &Config{
	KeyBagAlgorithm:  OidPBEWithSHAAnd3KeyTripleDESCBC,
	CertBagAlgorithm: OidPBEWithSHAAnd40BitRC2CBC,
	MACAlgorithm:     OidSHA1,
	Random:           rand.Reader,
	HasPassword:      true,
	Password:         "changeit",
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
// Default config)  and contains the certificates, and another that is
// unencrypted and contains the private key shrouded with 3DES  The private key
// bag and the end-entity certificate bag have the LocalKeyId attribute set to
// the SHA-1 fingerprint of the end-entity certificate.
func Encode(rand io.Reader, privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, password string) (pfxData []byte, err error) {
	d := DefaultConfig.Clone()
	d.Random = rand
	d.Password = password
	d.HasPassword = true

	entries := []CertEntry{CertEntry{
		Cert: certificate,
	}}
	for _, c := range caCerts {
		entries = append(entries, CertEntry{Cert: c})
	}

	return Marshal(&P12{
		KeyEntries:  []KeyEntry{KeyEntry{Key: privateKey}},
		CertEntries: entries,
	}, d)
}

// Encode produces pfxData containing private keys (PrivateKeys),
// an entity certificates (CertEntries), and any number of CA certificates
// included as CertEntries.
//
// The private key is encrypted with the provided password, but due to the
// weak encryption primitives used by PKCS#12, it is RECOMMENDED that you
// specify a hard-coded password (such as [DefaultPassword]) and protect
// the resulting pfxData using other means.
//
// The Config.Rand argument is used to provide entropy for the encryption, and
// can be set to [crypto/rand.Reader].
//
// Encode uses the P12 and specified Config with Algorithm specification for
// for securing the PFX.
//
// Example:
//
//   p := pkcs12.P12{
//     Password:    "changeit",
//     HasPassword: true,
//     Config:      pkcs12.DefaultConfig,
//   }
//   p.PrivateKeys = append(p.PrivateKeys, myKey)
//   p.CertEntries = append(p.CertEntries, pkcs12.CertEntry{Certificate: myCert})
//   raw, err := p.Encode()
func Marshal(p12 *P12, config *Config) (pfxData []byte, err error) {
	var encodedPassword []byte
	if config.HasPassword {
		encodedPassword, err = bmpStringZeroTerminated(config.Password)
		if err != nil {
			return nil, err
		}
	}

	for i, c := range p12.CertEntries {
		if err := checkCert(fmt.Sprintf("CA certificate #%d", i), c.Cert); err != nil {
			return pfxData, err
		}
		if err := p12.CertEntries[i].SetFingerPrint(); err != nil {
			return nil, err
		}
	}

	if config == nil {
		return nil, errors.New("pkcs12: no config provided for encoding")
	}
	if config.Random == nil {
		// Make sure we have a sensible value if none is specified
		config.Random = rand.Reader
	}

	pfx := pfxPdu{
		Version: 3,
	}

	var certBags []safeBag
	for _, ce := range p12.CertEntries {
		certBag, err := makeCertBag(ce.Cert.Raw, ce.Attributes)
		if err != nil {
			return nil, err
		}
		certBags = append(certBags, *certBag)
	}

	var keyBags []safeBag
	for _, k := range p12.KeyEntries {
		keyBag := &safeBag{
			Id: oidPKCS8ShroundedKeyBag,
			Value: asn1.RawValue{
				Class:      2,
				Tag:        0,
				IsCompound: true,
			}}

		if keyBag.Value.Bytes, err = encodePkcs8ShroudedKeyBag(config.Random, k.Key,
			encodedPassword, config.KeyBagAlgorithm); err != nil {
			return nil, err
		}

		pkcs12Attributes, err := localKeyID(k.Key)
		if err != nil {
			return nil, err
		}

		keyBag.Attributes = append(keyBag.Attributes, pkcs12Attributes...)
		keyBags = append(keyBags, *keyBag)
	}

	// Construct an authenticated safe with two SafeContents.
	// The first SafeContents is encrypted and contains the cert bags.
	// The second SafeContents is unencrypted and contains the shrouded key bag.
	var authenticatedSafe [2]contentInfo
	if authenticatedSafe[0], err = makeSafeContents(config, certBags, encodedPassword); err != nil {
		return nil, err
	}
	if authenticatedSafe[1], err = makeSafeContents(config, keyBags, nil); err != nil {
		return nil, err
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	// compute the MAC
	pfx.MacData.Mac.Algorithm.Algorithm = config.MACAlgorithm
	pfx.MacData.MacSalt = make([]byte, 8)
	if _, err = config.Random.Read(pfx.MacData.MacSalt); err != nil {
		return nil, err
	}
	pfx.MacData.Iterations = 1
	if err = computeMac(&pfx.MacData, authenticatedSafeBytes, encodedPassword); err != nil {
		return nil, err
	}

	pfx.AuthSafe.ContentType = oidDataContentType
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

// TrustStoreEntry represents an entry in a Java TrustStore.
type TrustStoreEntry struct {
	Cert         *x509.Certificate
	FriendlyName string
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
	conf := DefaultConfig.Clone()
	conf.Random = rand
	conf.Password = password
	conf.HasPassword = true
	return EncodeTrustStoreWithConfig(&TrustStore{
		Entries:     entries,
		HasPassword: true,
	}, conf)
}

// Encode produces pfxData containing any number of CA certificates (entries)
// to be trusted. The certificates will be marked with a special OID that allow
// it to be used as a Java TrustStore in Java 1.8 and newer.
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
// EncodeWithConfig takes a Config with Algorithm specifications to use for
// for securing the PFX.
func EncodeTrustStoreWithConfig(ts *TrustStore, config *Config) (pfxData []byte, err error) {
	var encodedPassword []byte
	if ts.HasPassword {
		encodedPassword, err = bmpStringZeroTerminated(config.Password)
		if err != nil {
			return nil, err
		}
	}

	for i, c := range ts.Entries {
		if err := checkCert(fmt.Sprintf("TrustStoreEntry #%d", i), c.Cert); err != nil {
			return pfxData, err
		}
	}

	if config == nil {
		return nil, errors.New("pkcs12: no config provided for encoding")
	}
	if config.Random == nil {
		// Make sure we have a sensible value if none is specified
		config.Random = rand.Reader
	}

	pfx := pfxPdu{
		Version: 3,
	}

	var certAttributes []pkcs12Attribute

	extKeyUsageOidBytes, err := asn1.Marshal(oidAnyExtendedKeyUsage)
	if err != nil {
		return nil, err
	}

	// the OidJavaTrustStore attribute contains the EKUs for which
	// this trust anchor will be valid
	certAttributes = append(certAttributes, pkcs12Attribute{
		Id: oidJavaTrustStore,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        17,
			IsCompound: true,
			Bytes:      extKeyUsageOidBytes,
		},
	})

	var certBags []safeBag
	for _, entry := range ts.Entries {

		bmpFriendlyName, err := bmpString(entry.FriendlyName)
		if err != nil {
			return nil, err
		}

		encodedFriendlyName, err := asn1.Marshal(asn1.RawValue{
			Class:      0,
			Tag:        30,
			IsCompound: false,
			Bytes:      bmpFriendlyName,
		})
		if err != nil {
			return nil, err
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

		certBag, err := makeCertBag(entry.Cert.Raw, append(certAttributes, friendlyName))
		if err != nil {
			return nil, err
		}
		certBags = append(certBags, *certBag)
	}

	// Construct an authenticated safe with one SafeContent.
	// The SafeContents is encrypted and contains the cert bags.
	var authenticatedSafe [1]contentInfo
	if authenticatedSafe[0], err = makeSafeContents(config, certBags, encodedPassword); err != nil {
		return nil, err
	}

	var authenticatedSafeBytes []byte
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	// compute the MAC
	pfx.MacData.Mac.Algorithm.Algorithm = config.MACAlgorithm
	pfx.MacData.MacSalt = make([]byte, 8)
	if _, err = rand.Read(pfx.MacData.MacSalt); err != nil {
		return nil, err
	}
	pfx.MacData.Iterations = 1
	if err = computeMac(&pfx.MacData, authenticatedSafeBytes, encodedPassword); err != nil {
		return nil, err
	}

	pfx.AuthSafe.ContentType = oidDataContentType
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

func makeCertBag(certBytes []byte, attributes []pkcs12Attribute) (certBag *safeBag, err error) {
	certBag = new(safeBag)
	certBag.Id = oidCertBag
	certBag.Value.Class = 2
	certBag.Value.Tag = 0
	certBag.Value.IsCompound = true
	if certBag.Value.Bytes, err = encodeCertBag(certBytes); err != nil {
		return nil, err
	}
	certBag.Attributes = attributes
	return
}

func makeSafeContents(config *Config, bags []safeBag, password []byte) (ci contentInfo, err error) {
	var data []byte
	if data, err = asn1.Marshal(bags); err != nil {
		return
	}

	if password == nil {
		ci.ContentType = oidDataContentType
		ci.Content.Class = 2
		ci.Content.Tag = 0
		ci.Content.IsCompound = true
		if ci.Content.Bytes, err = asn1.Marshal(data); err != nil {
			return
		}
	} else {
		randomSalt := make([]byte, 8)
		if _, err = config.Random.Read(randomSalt); err != nil {
			return
		}

		algo := pkix.AlgorithmIdentifier{Algorithm: config.CertBagAlgorithm}
		if algo.Parameters.FullBytes, err = asn1.Marshal(pbeParams{Salt: randomSalt, Iterations: 2048}); err != nil {
			return
		}

		var encryptedData encryptedData
		encryptedData.Version = 0
		encryptedData.EncryptedContentInfo.ContentType = oidDataContentType
		encryptedData.EncryptedContentInfo.ContentEncryptionAlgorithm = algo
		if err = pbEncrypt(&encryptedData.EncryptedContentInfo, data, password); err != nil {
			return
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
