package cmd

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

var version string = "local-development"

const (
	FlagServerName     = "server-name"
	FlagMinTlsVersion  = "min-tls"
	FlagMaxTlsVersion  = "max-tls"
	FlagExportRootPath = "export-root"
)

var rootCmd = &cobra.Command{
	Use:   "inspectls",
	Short: "inspectls inspects TLS endpoints' certificates",
	Long:  "inspectls helps inspecting certificates available on TLS endpoints",
	Args:  cobra.ExactArgs(1),

	Version: version,

	RunE: func(cmd *cobra.Command, args []string) error {
		for _, arg := range args {
			if err := inspect(cmd, arg); err != nil {
				return err
			}
		}

		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(rootCmd.OutOrStdout(), err)
		os.Exit(1)
	}
}

func init() {
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	fs := flag.NewFlagSet("", flag.PanicOnError)
	klog.InitFlags(fs)

	rootCmd.Flags().AddGoFlagSet(fs)

	rootCmd.Flags().StringP(FlagServerName, "s", "",
		"The name to pass to the server when SNI is used. If unset the argument "+
			"FQDN is used unless it is an IP address.")

	var (
		minTlsVersion, maxTlsVersion tlsVersion
	)
	rootCmd.Flags().VarP(&minTlsVersion, FlagMinTlsVersion, "m",
		`The minimum TLS version to use. Must be one of "ssl3.0", "tls1.0", "tls1.1", "tls1.2", "tls1.3".`)
	rootCmd.Flags().VarP(&maxTlsVersion, FlagMaxTlsVersion, "x",
		`The maximum TLS version to use. Must be one of "ssl3.0", "tls1.0", "tls1.1", "tls1.2", "tls1.3".`)

	rootCmd.Flags().StringP(FlagExportRootPath, "e", "",
		"The root path for exporting certificates in server-provided chain.")
}

type inspectContext struct {
	address        string
	serverName     string
	minTlsVersion  *uint16
	maxTlsVersion  *uint16
	exportRootPath string
}

func (c inspectContext) verifyCert(
	rawCerts [][]byte,
	verifiedChains [][]*x509.Certificate,
) error {
	fmt.Printf("Found %d certificates for %q.\n", len(rawCerts), c.address)

	var exportTemplate *string = nil
	if c.exportRootPath != "" {
		addr := strings.ReplaceAll(c.address, ":", "_")
		exportTemplate = new(path.Join(c.exportRootPath, addr))
	}

	for i, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if nil != err {
			fmt.Printf("Failed to parse certificate %d: %v\n", i, err)
			return err
		}

		if exportTemplate != nil {
			exportPath := fmt.Sprintf("%s_%d.crt", *exportTemplate, i)
			if err := saveCertificateAsPEM(cert, exportPath); err != nil {
				klog.ErrorS(err, "failed to export certificate", "path", exportPath)
			}
		}

		fmt.Printf("Certificate %d:\n", i)
		fmt.Printf("  Subject        : %s\n", cert.Subject.CommonName)
		fmt.Printf("  DNS Names      : %v\n", cert.DNSNames)
		fmt.Printf("  Email Addresses: %v\n", cert.EmailAddresses)
		fmt.Printf("  Serial Number  : %v\n", cert.SerialNumber)

		sha1Thumbprint := sha1.Sum(cert.Raw)
		fmt.Printf("  SHA1 Thumbprint: %v\n", hex.EncodeToString(sha1Thumbprint[:]))

		fmt.Printf("  IP Addresses   : %v\n", cert.IPAddresses)
		fmt.Printf("  Not Before     : %v\n", cert.NotBefore)
		fmt.Printf("  Not After      : %v\n", cert.NotAfter)
	}

	return nil
}

func (c inspectContext) verifyConn(connState tls.ConnectionState) error {
	fmt.Println("Connection details:")
	fmt.Printf("  Version        : %s\n", tls.VersionName(connState.Version))
	fmt.Printf("  Cipher Suite   : %s\n", tls.CipherSuiteName(connState.CipherSuite))
	fmt.Printf("  Server Name    : %s\n", connState.ServerName)

	return nil
}

func (c inspectContext) getTLSConfig() *tls.Config {
	config := tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: c.verifyCert,
		VerifyConnection:      c.verifyConn,
		ServerName:            c.serverName,
	}

	if c.minTlsVersion != nil {
		config.MinVersion = *c.minTlsVersion
	}
	if c.maxTlsVersion != nil {
		config.MaxVersion = *c.maxTlsVersion
	}

	return &config
}

func inspect(cmd *cobra.Command, address string) error {
	serverName := cmd.Flag(FlagServerName).Value.String()
	exportRootPath := cmd.Flag(FlagExportRootPath).Value.String()

	c := inspectContext{
		address:        address,
		serverName:     serverName,
		exportRootPath: exportRootPath,
	}

	minTlsVersion := cmd.Flag(FlagMinTlsVersion).Value.(*tlsVersion)
	if minTlsVersion != nil {
		c.minTlsVersion = minTlsVersion.getTlsVersion()
	}
	maxTlsVersion := cmd.Flag(FlagMaxTlsVersion).Value.(*tlsVersion)
	if maxTlsVersion != nil {
		c.maxTlsVersion = maxTlsVersion.getTlsVersion()
	}

	conn, err := tls.Dial("tcp", address, c.getTLSConfig())
	if err != nil {
		klog.ErrorS(err, "failed to dial", "address", address)
		return err
	}

	defer conn.Close()
	return nil
}

// saveCertificateAsPEM writes an x509.Certificate to a PEM file
func saveCertificateAsPEM(cert *x509.Certificate, filename string) error {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("failed to encode PEM: %w", err)
	}

	return nil
}
