package cmd

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

var version string

var rootCmd = &cobra.Command{
	Use:   "inspectls",
	Short: "inspectls inspects TLS endpoints' certificates",
	Long:  "inspectls helps inspecting certificates available on TLS endpoints",
	Args:  cobra.MinimumNArgs(1),

	Version: version,

	RunE: func(cmd *cobra.Command, args []string) error {
		for _, arg := range args {
			if err := inspect(arg); err != nil {
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
}

type inspectContext struct {
	address string
}

func (c inspectContext) verifyCert(
	rawCerts [][]byte,
	verifiedChains [][]*x509.Certificate,
) error {
	fmt.Printf("Found %d certificates for %q.\n", len(rawCerts), c.address)

	for i := 0; i < len(rawCerts); i++ {
		rawCert := rawCerts[i]

		cert, err := x509.ParseCertificate(rawCert)

		if nil != err {
			fmt.Printf("Failed to parse certificate %d: %v\n", i, err)

			return err
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

func (c inspectContext) getTLSConfig() *tls.Config {
	config := tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: c.verifyCert,
	}

	return &config
}

func inspect(address string) error {
	c := inspectContext{
		address: address,
	}
	conn, err := tls.Dial("tcp", address, c.getTLSConfig())
	if err != nil {
		klog.Errorf("failed to dial %q: %v", address, err)
		return err
	}

	defer conn.Close()
	return nil
}
