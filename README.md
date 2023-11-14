# package pkcs12

[![Documentation](https://pkg.go.dev/badge/github.com/pschou/go-pkcs12)](https://pkg.go.dev/github.com/pschou/go-pkcs12)

    import "github.com/pschou/go-pkcs12" 

Package pkcs12 implements some of PKCS#12 (also known as P12 or PFX).
It is intended for decoding DER-encoded P12/PFX files for use with the `crypto/tls`
package, and for encoding P12/PFX files for use by legacy applications which
do not support newer formats.  Since PKCS#12 uses weak encryption
primitives, it SHOULD NOT be used for new applications.

Note that only DER-encoded PKCS#12 files are supported, even though PKCS#12
allows BER encoding.  This is because encoding/asn1 only supports DER.

This package is forked from `golang.org/x/crypto/pkcs12`, which is frozen and `github.com/SSLMate/go-pkcs12`.
The implementation is distilled from https://tools.ietf.org/html/rfc7292
and referenced documents.
