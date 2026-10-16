//go:build chart

// Added by the balex42 fork: deployment contract checks on rendered Helm output.
package main

import (
	"context"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChartConfiguration(t *testing.T) {
	chart := "charts/cert-manager-webhook-infoblox-wapi"
	command := func(args ...string) ([]byte, error) {
		return exec.CommandContext(context.Background(), "helm", args...).CombinedOutput()
	}
	for _, tc := range []struct {
		name      string
		args      []string
		wantError bool
	}{
		{"default mounts", []string{"--set", "infoblox.host=infoblox.example.com"}, false},
		{"private CA and policy", []string{"-f", "tests/chart-values.yaml"}, false},
		{"host required", nil, true},
		{"legacy hostPath rejected", []string{"--set", "infoblox.host=example.com", "--set", "secretVolume.hostPath=/node/creds.json"}, true},
		{"invalid port", []string{"--set", "infoblox.host=example.com", "--set", "securePort=443"}, true},
		{"policy peers required", []string{"--set", "infoblox.host=example.com", "--set", "networkPolicy.enabled=true"}, true},
		{"invalid digest", []string{"--set", "infoblox.host=example.com", "--set", "image.digest=mutable"}, true},
		{"CA requires verification", []string{"--set", "infoblox.host=example.com", "--set", "infoblox.tls.verify=false", "--set", "infoblox.tls.caBundle.existingConfigMap=enterprise-ca"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"template", "test", chart, "--namespace", "webhook"}, tc.args...)
			out, err := command(args...)
			if tc.wantError {
				require.Error(t, err, string(out))
				return
			}
			require.NoError(t, err, string(out))
			text := string(out)
			assert.Contains(t, text, "--secure-port=8443")
			assert.Contains(t, text, "containerPort: 8443")
			assert.Contains(t, text, "targetPort: https")
			assert.Contains(t, text, "mountPath: /etc/secrets")
			assert.NotContains(t, text, "subPath:")
			assert.NotContains(t, text, "hostPath:")
			if tc.name == "private CA and policy" {
				assert.Contains(t, text, "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
				assert.Contains(t, text, `secretName: "shared-credentials"`)
				assert.Contains(t, text, `key: "account.json"`)
				assert.Contains(t, text, "value: /etc/infoblox-ca/ca.crt")
				assert.Contains(t, text, `name: "enterprise-ca"`)
				assert.Contains(t, text, "cidr: 192.0.2.10/32")
				assert.Contains(t, text, "port: 6443")
			}
		})
	}
}
