// Added by the balex42 fork: TLS policy and transport failure regressions.
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvironmentDefaultsAndValidation(t *testing.T) {
	for _, name := range []string{"INFOBLOX_PORT", "INFOBLOX_VERSION", "INFOBLOX_TLS_VERIFY", "INFOBLOX_CA_FILE", "INFOBLOX_HTTP_TIMEOUT", "INFOBLOX_HTTP_POOL_CONNECTIONS"} {
		t.Setenv(name, "")
	}
	t.Setenv("INFOBLOX_HOST", "infoblox.example.com")
	s, err := settingsFromEnvironment()
	require.NoError(t, err)
	assert.True(t, s.verify)
	assert.Equal(t, "443", s.port)
	assert.Equal(t, SecretPath, s.credentialsPath)
	for key, value := range map[string]string{
		"INFOBLOX_HOST": "https://bad.example/path", "INFOBLOX_PORT": "0",
		"INFOBLOX_VERSION": "../../evil", "INFOBLOX_TLS_VERIFY": "invalid",
		"INFOBLOX_HTTP_TIMEOUT": "0", "INFOBLOX_HTTP_POOL_CONNECTIONS": "-1",
	} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, value)
			_, err := settingsFromEnvironment()
			require.Error(t, err)
		})
	}
	t.Setenv("INFOBLOX_CA_FILE", "/ca.crt")
	t.Setenv("INFOBLOX_TLS_VERIFY", "false")
	_, err = settingsFromEnvironment()
	require.ErrorContains(t, err, "requires TLS verification")
}

func TestWAPITLS(t *testing.T) {
	solver, _ := newTestSolver(t)
	require.NoError(t, solver.Present(challenge("value", "External")))
	// Removing trust must fail, rather than silently disabling verification.
	trustedPath := solver.settings.caPath
	solver.settings.caPath = ""
	err := solver.Present(challenge("private-value", "External"))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "private-value")
	solver.settings.caPath = trustedPath
	solver.settings.host = "localhost" // Test certificate covers 127.0.0.1, not localhost.
	require.Error(t, solver.Present(challenge("value", "External")))
}

func TestInvalidCABundleFailsClosed(t *testing.T) {
	solver, _ := newTestSolver(t)
	for _, content := range []string{"", "not a certificate", "-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----"} {
		require.NoError(t, os.WriteFile(solver.settings.caPath, []byte(content), 0o600))
		_, err := solver.getIbClient()
		require.ErrorContains(t, err, "internal CA bundle")
	}
	solver.settings.caPath = filepath.Join(t.TempDir(), "missing.crt")
	_, err := solver.getIbClient()
	require.ErrorContains(t, err, "read internal CA bundle")
}

func TestWAPIRedirectAndResponseValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"redirect", http.StatusTemporaryRedirect, "private-value"},
		{"error body", http.StatusForbidden, "private-value"},
		{"invalid JSON", http.StatusOK, "private-value"},
		{"wrong JSON shape", http.StatusOK, `{"error":"private-value"}`},
		{"invalid TXT fields", http.StatusOK, `[{"text":{"value":"private-value"}}]`},
		{"oversized", http.StatusOK, strings.Repeat(" ", (1<<20)+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			redirected := false
			destination := httptest.NewServer(http.HandlerFunc(func(out http.ResponseWriter, _ *http.Request) {
				redirected = true
				_, _ = out.Write([]byte(`[]`))
			}))
			defer destination.Close()
			server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, _ *http.Request) {
				out.Header().Set("Location", destination.URL)
				out.WriteHeader(tc.status)
				_, _ = out.Write([]byte(tc.body))
			}))
			defer server.Close()
			r, err := newWAPIRequestor(deploymentSettings{verify: false, timeout: 2, poolConnections: 1})
			require.NoError(t, err)
			defer r.client.CloseIdleConnections()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"?text=private-value", http.NoBody)
			require.NoError(t, err)
			req.SetBasicAuth("user", "password")
			_, err = r.SendRequest(req)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "private-value")
			assert.False(t, redirected)
		})
	}
}

func TestCABundleReload(t *testing.T) {
	solver, _ := newTestSolver(t)
	valid, err := os.ReadFile(solver.settings.caPath)
	require.NoError(t, err)
	ch := challenge("value", "External")
	require.NoError(t, solver.Present(ch))
	// Even a partly valid bundle must be rejected after a ConfigMap update.
	require.NoError(t, os.WriteFile(solver.settings.caPath, append(valid, []byte("invalid trailing certificate")...), 0o600))
	require.ErrorContains(t, solver.CleanUp(ch), "internal CA bundle")
	malformed := []byte("-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----\n")
	require.NoError(t, os.WriteFile(solver.settings.caPath, append(malformed, valid...), 0o600))
	require.ErrorContains(t, solver.CleanUp(ch), "internal CA bundle")
	require.NoError(t, os.WriteFile(solver.settings.caPath, valid, 0o600))
	require.NoError(t, solver.CleanUp(ch))
}
