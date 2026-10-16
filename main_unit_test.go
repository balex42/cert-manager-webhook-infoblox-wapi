// Modified by the balex42 fork: exercise the real connector against a TLS WAPI stub.
package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestLoadConfig(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		wantError bool
	}{
		{"valid", `{"view":"External","ttl":600,"useTtl":false}`, false},
		{"defaults", `{"view":"External"}`, false},
		{"missing view", `{}`, true},
		{"bad JSON", `invalid`, true},
		{"null", `null`, true},
		{"negative TTL", `{"view":"External","ttl":-1}`, true},
		{"endpoint override", `{"view":"External","host":"attacker.example"}`, true},
		{"TLS override", `{"view":"External","sslVerify":false}`, true},
		{"credentials override", `{"view":"External","getUserFromVolume":true}`, true},
		{"trailing document", `{"view":"External"}{}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadConfig(&apiextensionsv1.JSON{Raw: []byte(tc.raw)})
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.name == "defaults" {
				assert.Equal(t, uint32(300), cfg.TTL)
				assert.True(t, cfg.UseTTL)
			} else {
				assert.Equal(t, uint32(600), cfg.TTL)
				assert.False(t, cfg.UseTTL)
			}
		})
	}
	_, err := loadConfig(nil)
	require.Error(t, err)
}

func TestReadCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	_, err := readCredentials(path)
	require.Error(t, err)
	for _, content := range []string{`{"username":"user"}`, `null`, `{"password":"private-value"}`, `{"username":123,"password":"private-value"}`, `private-value`} {
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		_, err := readCredentials(path)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "private-value")
	}
	for _, password := range []string{"first", "rotated", " spaces are preserved "} {
		data, err := json.Marshal(usernamePassword{Username: "user", Password: password})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, data, 0o600))
		creds, err := readCredentials(path)
		require.NoError(t, err)
		assert.Equal(t, password, creds.Password)
	}
}

type testTXT struct {
	Ref    string `json:"_ref"`
	Name   string `json:"name"`
	Text   string `json:"text"`
	View   string `json:"view"`
	TTL    uint32 `json:"ttl"`
	UseTTL bool   `json:"use_ttl"`
}

type testWAPI struct {
	mu                                       sync.Mutex
	records                                  map[string]testTXT
	creates, deletes                         int
	lookupStatus, createStatus, deleteStatus int
	createThenFail                           bool
	password                                 string
}

func (w *testWAPI) ServeHTTP(out http.ResponseWriter, req *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	user, password, ok := req.BasicAuth()
	if !ok || user != "user" || password != w.password {
		http.Error(out, "bad credentials", http.StatusUnauthorized)
		return
	}
	out.Header().Set("Content-Type", "application/json")
	switch req.Method {
	case http.MethodGet:
		if w.lookupStatus != 0 {
			http.Error(out, "private-value", w.lookupStatus)
			return
		}
		matches := []testTXT{}
		for _, record := range w.records {
			if record.Name == req.URL.Query().Get("name") && record.Text == req.URL.Query().Get("text") && record.View == req.URL.Query().Get("view") {
				matches = append(matches, record)
			}
		}
		_ = json.NewEncoder(out).Encode(matches)
	case http.MethodPost:
		if w.createStatus != 0 {
			http.Error(out, "private-value", w.createStatus)
			return
		}
		var record testTXT
		if err := json.NewDecoder(req.Body).Decode(&record); err != nil {
			http.Error(out, "invalid record", http.StatusBadRequest)
			return
		}
		for _, existing := range w.records {
			if existing.Name == record.Name && existing.Text == record.Text && existing.View == record.View {
				http.Error(out, "duplicate private-value", http.StatusBadRequest)
				return
			}
		}
		w.creates++
		record.Ref = fmt.Sprintf("record:txt/%d", w.creates)
		w.records[record.Ref] = record
		if w.createThenFail {
			http.Error(out, "private-value", http.StatusServiceUnavailable)
			return
		}
		out.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(out).Encode(record.Ref)
	case http.MethodDelete:
		if w.deleteStatus != 0 {
			http.Error(out, "private-value", w.deleteStatus)
			return
		}
		ref := strings.TrimPrefix(req.URL.Path, "/wapi/v2.10/")
		if _, ok := w.records[ref]; !ok {
			http.Error(out, "gone", http.StatusNotFound)
			return
		}
		delete(w.records, ref)
		w.deletes++
		_ = json.NewEncoder(out).Encode(ref)
	default:
		http.Error(out, "unsupported method", http.StatusMethodNotAllowed)
	}
}

func newTestSolver(t *testing.T) (*customDNSProviderSolver, *testWAPI) {
	t.Helper()
	wapi := &testWAPI{records: map[string]testTXT{}, password: "password"}
	server := httptest.NewTLSServer(wapi)
	t.Cleanup(server.Close)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	require.NoError(t, err)
	dir := t.TempDir()
	credsPath := filepath.Join(dir, "creds.json")
	require.NoError(t, os.WriteFile(credsPath, []byte(`{"username":"user","password":"password"}`), 0o600))
	caPath := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600))
	return &customDNSProviderSolver{settings: deploymentSettings{
		host: host, port: port, version: "2.10", credentialsPath: credsPath,
		caPath: caPath, verify: true, timeout: 5, poolConnections: 2,
	}}, wapi
}

func challenge(value, view string) *whapi.ChallengeRequest {
	config, _ := json.Marshal(customDNSProviderConfig{View: view, TTL: 600, UseTTL: true})
	return &whapi.ChallengeRequest{
		DNSName: "example.com", ResolvedFQDN: "_acme-challenge.example.com.", Key: value,
		AllowAmbientCredentials: true, ResourceNamespace: "cert-manager",
		Config: &apiextensionsv1.JSON{Raw: config},
	}
}

func TestPresentAndCleanup(t *testing.T) {
	solver, wapi := newTestSolver(t)
	assert.Equal(t, "infoblox-wapi", solver.Name())
	assert.Equal(t, "_acme-challenge.example.com", solver.DeDot("_acme-challenge.example.com."))
	a := challenge("apex-value", "External")
	b := challenge("wildcard-value", "External")
	b.DNSName = "*.example.com"
	otherView := challenge("apex-value", "Internal")
	for _, ch := range []*whapi.ChallengeRequest{a, a, b, otherView} {
		require.NoError(t, solver.Present(ch))
	}
	assert.Len(t, wapi.records, 3)
	assert.Equal(t, 3, wapi.creates)
	assert.Zero(t, wapi.deletes)
	for _, record := range wapi.records {
		assert.Equal(t, uint32(600), record.TTL)
		assert.True(t, record.UseTTL)
	}
	require.NoError(t, solver.CleanUp(a))
	require.NoError(t, solver.CleanUp(a))
	assert.Len(t, wapi.records, 2)
	for _, record := range wapi.records {
		assert.True(t, record.Text == b.Key || record.View == "Internal")
	}
	require.NoError(t, solver.CleanUp(b))
	require.NoError(t, solver.CleanUp(otherView))
	assert.Empty(t, wapi.records)
}

func TestConcurrentPresentationAndCleanup(t *testing.T) {
	solver, wapi := newTestSolver(t)
	// Two values at the same name, each concurrently presented by several callers.
	var wg sync.WaitGroup
	errors := make(chan error, 20)
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- solver.Present(challenge(fmt.Sprintf("value-%d", i%2), "External"))
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	assert.Len(t, wapi.records, 2)
	assert.Equal(t, 2, wapi.creates)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, solver.CleanUp(challenge("value-0", "External")))
		}()
	}
	wg.Wait()
	assert.Len(t, wapi.records, 1)
	for _, record := range wapi.records {
		assert.Equal(t, "value-1", record.Text)
	}
}

func TestCreateResponseLost(t *testing.T) {
	solver, wapi := newTestSolver(t)
	wapi.createThenFail = true
	require.NoError(t, solver.Present(challenge("value", "External")))
	assert.Equal(t, 1, wapi.creates)
}

func TestWAPIFailures(t *testing.T) {
	for _, operation := range []string{"lookup", "create", "delete"} {
		t.Run(operation, func(t *testing.T) {
			solver, wapi := newTestSolver(t)
			ch := challenge("private-value", "External")
			var err error
			switch operation {
			case "lookup":
				wapi.lookupStatus = http.StatusForbidden
				err = solver.Present(ch)
			case "create":
				wapi.createStatus = http.StatusServiceUnavailable
				err = solver.Present(ch)
			case "delete":
				require.NoError(t, solver.Present(ch))
				wapi.deleteStatus = http.StatusForbidden
				err = solver.CleanUp(ch)
			}
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "private-value")
		})
	}
}

func TestSharedCredentialAuthorizationAndRotation(t *testing.T) {
	solver, wapi := newTestSolver(t)
	ch := challenge("value", "External")
	ch.AllowAmbientCredentials = false
	require.ErrorContains(t, solver.Present(ch), "AllowAmbientCredentials")
	require.ErrorContains(t, solver.CleanUp(ch), "AllowAmbientCredentials")
	assert.Zero(t, wapi.creates)
	ch.AllowAmbientCredentials = true
	ch.ResourceNamespace = "application-a"
	require.NoError(t, solver.Present(ch))
	// A projected Secret update is picked up by the next operation, even in another namespace.
	require.NoError(t, os.WriteFile(solver.settings.credentialsPath, []byte(`{"username":"user","password":"rotated"}`), 0o600))
	wapi.password = "rotated"
	ch.ResourceNamespace = "application-b"
	require.NoError(t, solver.CleanUp(ch))
	assert.Empty(t, wapi.records)
}

type errorConnector struct{ ibclient.IBConnector }

func (*errorConnector) GetObject(_ ibclient.IBObject, _ string, _ *ibclient.QueryParams, result interface{}) error {
	// A connector error must not be swallowed just because it also returned data.
	*result.(*[]ibclient.RecordTXT) = []ibclient.RecordTXT{{Ref: "record:txt/1"}}
	return fmt.Errorf("lookup failed")
}

func TestLookupDoesNotSwallowErrors(t *testing.T) {
	solver := &customDNSProviderSolver{}
	_, err := solver.GetTXTRecord(&errorConnector{}, "name", "value", "view")
	require.ErrorContains(t, err, "lookup failed")
}
