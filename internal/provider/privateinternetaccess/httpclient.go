package privateinternetaccess

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/qdm12/gluetun/internal/constants"
)

func newHTTPClient(serverName string) (client *http.Client, err error) {
	certificateBytes, err := base64.StdEncoding.DecodeString(constants.PiaCAStrong)
	if err != nil {
		return nil, fmt.Errorf("cannot parse X509 certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse X509 certificate: %w", err)
	}

	//nolint:gomnd
	transport := &http.Transport{
		// Settings taken from http.DefaultTransport
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(certificate)
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}

	const httpTimeout = 30 * time.Second
	return &http.Client{
		Transport: transport,
		Timeout:   httpTimeout,
	}, nil
}
