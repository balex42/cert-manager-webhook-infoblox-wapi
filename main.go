// Package main implements a cert-manager ACME DNS01 webhook for Infoblox WAPI.
// Based on the cert-manager webhook example and the implementations by
// Luis Gracia and Dave Sargent. Modified for shared mounted credentials and TLS.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

// SecretPath is the fixed mount location of the shared credentials file.
const SecretPath = "/etc/secrets/creds.json" //nolint:gosec // Fixed file path, not a credential.

func main() {
	groupName := os.Getenv("GROUP_NAME")
	if groupName == "" {
		panic("GROUP_NAME must be specified")
	}
	cmd.RunWebhookServer(groupName, &customDNSProviderSolver{})
}

var _ webhook.Solver = (*customDNSProviderSolver)(nil)

type customDNSProviderSolver struct {
	settings deploymentSettings
}

// Endpoint, credentials, and TLS policy are deliberately not Issuer settings.
type customDNSProviderConfig struct {
	View   string `json:"view"`
	TTL    uint32 `json:"ttl"`
	UseTTL bool   `json:"useTtl"`
}

type usernamePassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c *customDNSProviderSolver) Name() string { return "infoblox-wapi" }

func (c *customDNSProviderSolver) Present(ch *whapi.ChallengeRequest) error {
	cfg, ib, err := c.prepare(ch)
	if err != nil {
		return err
	}
	recordName := c.DeDot(ch.ResolvedFQDN)
	ref, err := c.GetTXTRecord(ib, recordName, ch.Key, cfg.View)
	if err != nil || ref != "" {
		return err
	}
	if _, err := c.CreateTXTRecord(ib, recordName, ch.Key, cfg.View, cfg.TTL, cfg.UseTTL); err != nil {
		// Another replica may have created it, or the create response may have
		// been lost. Only an exact lookup can establish that presentation succeeded.
		if ref, lookupErr := c.GetTXTRecord(ib, recordName, ch.Key, cfg.View); lookupErr == nil && ref != "" {
			return nil
		}
		return err
	}
	klog.InfoS("Presented TXT record", "name", recordName, "view", cfg.View)
	return nil
}

func (c *customDNSProviderSolver) CleanUp(ch *whapi.ChallengeRequest) error {
	cfg, ib, err := c.prepare(ch)
	if err != nil {
		return err
	}
	recordName := c.DeDot(ch.ResolvedFQDN)
	ref, err := c.GetTXTRecord(ib, recordName, ch.Key, cfg.View)
	if err != nil || ref == "" {
		return err
	}
	if err := c.DeleteTXTRecord(ib, ref); err != nil {
		var notFound *ibclient.NotFoundError
		if !errors.As(err, &notFound) {
			return err
		}
	}
	klog.InfoS("Cleaned up TXT record", "name", recordName, "view", cfg.View)
	return nil
}

func (c *customDNSProviderSolver) prepare(ch *whapi.ChallengeRequest) (customDNSProviderConfig, ibclient.IBConnector, error) {
	if ch == nil {
		return customDNSProviderConfig{}, nil, errors.New("challenge request is required")
	}
	if !ch.AllowAmbientCredentials {
		return customDNSProviderConfig{}, nil, errors.New("shared mounted credentials require AllowAmbientCredentials; use an authorized ClusterIssuer or explicitly enable Issuer ambient credentials in cert-manager")
	}
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return cfg, nil, err
	}
	if c.DeDot(ch.ResolvedFQDN) == "" || ch.Key == "" {
		return cfg, nil, errors.New("resolved FQDN and challenge key are required")
	}
	ib, err := c.getIbClient()
	return cfg, ib, err
}

// Initialize validates local configuration without contacting WAPI. Kubernetes
// authentication and authorization are managed by the webhook server library.
func (c *customDNSProviderSolver) Initialize(_ *rest.Config, _ <-chan struct{}) error {
	settings, err := settingsFromEnvironment()
	if err != nil {
		return err
	}
	if _, err := readCredentials(settings.credentialsPath); err != nil {
		return err
	}
	if _, err := settings.tlsConfig(); err != nil {
		return err
	}
	c.settings = settings
	return nil
}

func loadConfig(raw *apiextensionsv1.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{TTL: 300, UseTTL: true}
	if raw == nil {
		return cfg, errors.New("solver config with a DNS view is required")
	}
	// Validate the whole document first, including trailing JSON values.
	if !json.Valid(raw.Raw) || string(raw.Raw) == "null" {
		return cfg, errors.New("invalid solver JSON configuration")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw.Raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("invalid solver config (only view, ttl, and useTtl are supported): %w", err)
	}
	if strings.TrimSpace(cfg.View) == "" {
		return cfg, errors.New("solver config requires a DNS view")
	}
	if cfg.TTL == 0 {
		cfg.TTL = 300
	}
	return cfg, nil
}

func (c *customDNSProviderSolver) getIbClient() (ibclient.IBConnector, error) {
	if c.settings.host == "" {
		return nil, errors.New("WAPI deployment settings have not been initialized")
	}
	creds, err := readCredentials(c.settings.credentialsPath)
	if err != nil {
		return nil, err
	}
	requestor, err := newWAPIRequestor(c.settings)
	if err != nil {
		return nil, err
	}
	return ibclient.NewConnector(
		ibclient.HostConfig{Host: c.settings.host, Port: c.settings.port, Version: c.settings.version},
		ibclient.AuthConfig{Username: creds.Username, Password: creds.Password},
		ibclient.NewTransportConfig("true", c.settings.timeout, c.settings.poolConnections),
		&ibclient.WapiRequestBuilder{}, requestor,
	)
}

func readCredentials(path string) (usernamePassword, error) {
	var creds usernamePassword
	data, err := os.ReadFile(path) //nolint:gosec // Path is deployment-controlled, never supplied by an Issuer.
	if err != nil {
		return creds, fmt.Errorf("read mounted credentials: %w", err)
	}
	if err := json.Unmarshal(data, &creds); err != nil {
		// Decoder errors may include source data; do not return them.
		return creds, errors.New("mounted credentials must be a JSON object containing username and password strings")
	}
	if strings.TrimSpace(creds.Username) == "" || creds.Password == "" {
		return creds, errors.New("mounted credentials require nonempty username and password")
	}
	return creds, nil
}

// GetTXTRecord returns the reference matching the exact name, value, and view.
func (c *customDNSProviderSolver) GetTXTRecord(ib ibclient.IBConnector, name, text, view string) (string, error) {
	var records []ibclient.RecordTXT
	err := ib.GetObject(ibclient.NewEmptyRecordTXT(), "", ibclient.NewQueryParams(false, map[string]string{
		"name": name, "text": text, "view": view,
	}), &records)
	var notFound *ibclient.NotFoundError
	if errors.As(err, &notFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if len(records) > 0 {
		return records[0].Ref, nil
	}
	return "", nil
}

// CreateTXTRecord adds a value without replacing other records at the same name.
func (c *customDNSProviderSolver) CreateTXTRecord(ib ibclient.IBConnector, name, text, view string, ttl uint32, useTTL bool) (string, error) {
	return ib.CreateObject(ibclient.NewRecordTXT(view, "", name, text, ttl, useTTL, "", nil))
}

// DeleteTXTRecord deletes a single WAPI object by reference.
func (c *customDNSProviderSolver) DeleteTXTRecord(ib ibclient.IBConnector, ref string) error {
	_, err := ib.DeleteObject(ref)
	return err
}

// DeDot removes the trailing dot from a fully qualified domain name.
func (c *customDNSProviderSolver) DeDot(fqdn string) string { return strings.TrimSuffix(fqdn, ".") }
