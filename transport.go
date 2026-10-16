// Shared-account deployment configuration and verified WAPI transport.
// Added by the balex42 fork; see NOTICE for upstream attributions.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
)

type deploymentSettings struct {
	host, port, version, credentialsPath, caPath string
	verify                                       bool
	timeout, poolConnections                     int
}

func settingsFromEnvironment() (deploymentSettings, error) {
	s := deploymentSettings{
		host: os.Getenv("INFOBLOX_HOST"), port: "443", version: "2.10",
		credentialsPath: SecretPath, caPath: os.Getenv("INFOBLOX_CA_FILE"),
		verify: true, timeout: 60, poolConnections: 10,
	}
	if s.host == "" || strings.ContainsAny(s.host, "/:@?# \\\t\r\n") {
		return s, errors.New("INFOBLOX_HOST must be a hostname or IPv4 address without scheme, port, or path")
	}
	if value := os.Getenv("INFOBLOX_PORT"); value != "" {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return s, errors.New("INFOBLOX_PORT must be between 1 and 65535")
		}
		s.port = value
	}
	if value := os.Getenv("INFOBLOX_VERSION"); value != "" {
		s.version = value
	}
	for _, component := range strings.Split(s.version, ".") {
		if _, err := strconv.ParseUint(component, 10, 16); err != nil {
			return s, errors.New("INFOBLOX_VERSION must be a dotted numeric WAPI version")
		}
	}
	if value := os.Getenv("INFOBLOX_TLS_VERIFY"); value != "" {
		verify, err := strconv.ParseBool(value)
		if err != nil {
			return s, errors.New("INFOBLOX_TLS_VERIFY must be a boolean")
		}
		s.verify = verify
	}
	if !s.verify && s.caPath != "" {
		return s, errors.New("an internal CA bundle requires TLS verification to be enabled")
	}
	if err := s.loadHTTPSettings(); err != nil {
		return s, err
	}
	return s, nil
}

func (s *deploymentSettings) loadHTTPSettings() error {
	for key, target := range map[string]*int{
		"INFOBLOX_HTTP_TIMEOUT": &s.timeout, "INFOBLOX_HTTP_POOL_CONNECTIONS": &s.poolConnections,
	} {
		if value := os.Getenv(key); value != "" {
			number, err := strconv.Atoi(value)
			if err != nil || number < 1 || number > 3600 {
				return fmt.Errorf("%s must be between 1 and 3600", key)
			}
			*target = number
		}
	}
	return nil
}

func (s deploymentSettings) tlsConfig() (*tls.Config, error) {
	config := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: !s.verify, //nolint:gosec // Explicit deployment-only opt-out; defaults to verification.
	}
	if s.caPath == "" {
		return config, nil
	}
	if !s.verify {
		return nil, errors.New("an internal CA bundle requires TLS verification")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system CA certificates: %w", err)
	}
	bundle, err := os.ReadFile(s.caPath) //nolint:gosec // Deployment-controlled mount path.
	if err != nil {
		return nil, fmt.Errorf("read internal CA bundle: %w", err)
	}
	if err := appendCABundle(roots, bundle); err != nil {
		return nil, err
	}
	config.RootCAs = roots
	return config, nil
}

func appendCABundle(roots *x509.CertPool, bundle []byte) error {
	count := 0
	for len(bytes.TrimSpace(bundle)) > 0 {
		bundle = bytes.TrimSpace(bundle)
		if !bytes.HasPrefix(bundle, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("internal CA bundle must contain only PEM certificates")
		}
		// Decode one block at a time: pem.Decode otherwise skips a malformed
		// first block when a later certificate is valid.
		const endMarker = "-----END CERTIFICATE-----"
		end := bytes.Index(bundle, []byte(endMarker))
		if end < 0 {
			return errors.New("internal CA bundle contains an incomplete PEM certificate")
		}
		end += len(endMarker)
		block, rest := pem.Decode(bundle[:end])
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return errors.New("internal CA bundle contains an invalid PEM certificate")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.New("internal CA bundle contains an invalid X.509 certificate")
		}
		roots.AddCert(certificate)
		bundle = bundle[end:]
		count++
	}
	if count == 0 {
		return errors.New("internal CA bundle contains no PEM certificates")
	}
	return nil
}

type wapiRequestor struct {
	client  *http.Client
	timeout time.Duration
}

var _ ibclient.HttpRequestor = (*wapiRequestor)(nil)

func newWAPIRequestor(s deploymentSettings) (*wapiRequestor, error) {
	tlsConfig, err := s.tlsConfig()
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(s.timeout) * time.Second
	transport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		DialContext:     (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: tlsConfig, TLSHandshakeTimeout: timeout,
		MaxIdleConnsPerHost: s.poolConnections, IdleConnTimeout: 30 * time.Second,
	}
	return &wapiRequestor{
		timeout: timeout,
		client: &http.Client{
			Transport: transport, Timeout: timeout,
			// WAPI should not redirect; never forward authentication or record data.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Init satisfies the client interface. Configuration was validated in the constructor.
func (r *wapiRequestor) Init(_ ibclient.AuthConfig, _ ibclient.TransportConfig) {}

func (r *wapiRequestor) SendRequest(req *http.Request) ([]byte, error) {
	ctx, cancel := context.WithTimeout(req.Context(), r.timeout)
	defer cancel()
	response, err := r.client.Do(req.Clone(ctx))
	if err != nil {
		// url.Error includes the query (TXT values) or reference in its URL.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("WAPI transport failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusNotFound {
		return nil, ibclient.NewNotFoundError("WAPI object not found (HTTP 404)")
	}
	success := response.StatusCode == http.StatusOK || (response.StatusCode == http.StatusCreated && req.Method == http.MethodPost)
	if !success {
		// WAPI error bodies can echo the TXT value and must not reach logs.
		return nil, fmt.Errorf("WAPI returned HTTP %d", response.StatusCode)
	}
	const maxResponse = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return nil, errors.New("could not read WAPI response")
	}
	if len(body) > maxResponse || !validWAPIResponse(req.Method, body) {
		// The upstream connector logs JSON decoding failures with the raw body.
		// Validate its expected response shape here so those paths cannot echo TXT data.
		return nil, errors.New("WAPI returned an oversized or invalid JSON response")
	}
	return body, nil
}

func validWAPIResponse(method string, body []byte) bool {
	if method == http.MethodGet {
		var records []ibclient.RecordTXT
		return json.Unmarshal(body, &records) == nil && records != nil
	}
	var ref string
	return json.Unmarshal(body, &ref) == nil && ref != ""
}
