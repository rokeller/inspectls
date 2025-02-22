package cmd

import (
	"crypto/tls"
	"errors"
)

type tlsVersion string

const (
	ssl30 tlsVersion = "ssl3.0" // SSL3.0 is no longer supported by the golang package used
	tls10 tlsVersion = "tls1.0"
	tls11 tlsVersion = "tls1.1"
	tls12 tlsVersion = "tls1.2"
	tls13 tlsVersion = "tls1.3"
)

func (v *tlsVersion) String() string {
	return string(*v)
}

func (v *tlsVersion) Set(vv string) error {
	switch vv {
	case
		"ssl3.0",
		"tls1.0",
		"tls1.1",
		"tls1.2",
		"tls1.3":
		*v = tlsVersion(vv)
		return nil

	default:
		return errors.New(`must be one of "ssl3.0", "tls1.0", "tls1.1", "tls1.2", "tls1.3"`)
	}
}

func (v *tlsVersion) Type() string {
	return "tlsVersion"
}

func (v *tlsVersion) getTlsVersion() *uint16 {
	var version uint16
	switch *v {
	case ssl30:
		version = tls.VersionSSL30
	case tls10:
		version = tls.VersionTLS10
	case tls11:
		version = tls.VersionTLS11
	case tls12:
		version = tls.VersionTLS12
	case tls13:
		version = tls.VersionTLS13

	default:
		return nil
	}

	return &version
}
