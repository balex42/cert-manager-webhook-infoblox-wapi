# cert-manager Infoblox WAPI webhook

[![CI](https://github.com/balex42/cert-manager-webhook-infoblox-wapi/actions/workflows/ci.yml/badge.svg)](https://github.com/balex42/cert-manager-webhook-infoblox-wapi/actions/workflows/ci.yml)
[![Helm](https://github.com/balex42/cert-manager-webhook-infoblox-wapi/actions/workflows/helm.yml/badge.svg)](https://github.com/balex42/cert-manager-webhook-infoblox-wapi/actions/workflows/helm.yml)

DNS-01 solver for cert-manager using Infoblox WAPI, hardened for **one shared
Infoblox account**, mounted Kubernetes credentials, and an optional internal CA.

This fork is based on [sarg3nt/cert-manager-webhook-infoblox-wapi](https://github.com/sarg3nt/cert-manager-webhook-infoblox-wapi).
The deployment configuration described here replaces the upstream credential and
connection configuration. See [migration](#migration-from-upstream).

## Architecture

- The webhook mounts an existing Secret in its own namespace at
  `/etc/secrets/creds.json`. Its service account does not need Secret-reading RBAC.
- The WAPI host, port, version, and TLS policy are deployment-controlled.
  Issuers cannot redirect the shared credentials to another endpoint.
- TLS certificate and hostname verification default to enabled. An optional
  ConfigMap supplies internal CA certificates **in addition to system trust**.
  Missing or malformed configured bundles fail closed; authenticated redirects
  are rejected. TLS 1.2 or newer is required.
- Credentials and CA files are reread for each operation. Kubernetes projected
  volume updates take effect after propagation, without restarting the webhook.
- The container runs as UID/GID 65532, listens on 8443, and is exposed through a
  Service on 443. The image uses digest-pinned Chainguard Go and Static stages.
- `Present()` preserves existing matching records; cleanup targets the exact
  name, value, and DNS view. Other TXT values at the same name are preserved.

Mounted credentials are ambient credentials: the solver honors cert-manager's
`AllowAmbientCredentials`. Use a `ClusterIssuer` with cluster-issuer ambient
credentials enabled (cert-manager's usual default). Namespaced Issuers require
explicitly enabling issuer ambient credentials in cert-manager. Such Issuers can
use the shared account's DNS permissions, so grant that capability only to trusted
Issuer administrators and scope the Infoblox account's permissions accordingly.

For API-based credential providers, cert-manager supplies an Issuer's namespace
or the configured cluster-resource namespace for a ClusterIssuer. A ClusterIssuer
does not inherently require copying credentials into application namespaces.
This fork's mounted-account design is independent of that namespace selection.

## Installation

Install cert-manager first. Choose a unique webhook API group that you control,
such as `acme.example.com`. The same value must appear in Helm and Issuer settings.

### 1. Create credentials

Create a protected local `creds.json` file with ordinary JSON strings:

```json
{"username":"cert-manager-service-account","password":"replace-me"}
```

Do not base64-encode the individual JSON values. Kubernetes handles Secret data
encoding. Create the namespace and Secret using your usual secret-management
process, or:

```sh
kubectl create namespace infoblox-webhook
kubectl -n infoblox-webhook create secret generic infoblox-credentials \
  --from-file=creds.json=/secure/path/creds.json
```

The chart references this Secret; it does not put credentials into Helm values.

### 2. Supply your internal CA

For a private-PKI WAPI endpoint, put the issuing CA chain in a PEM bundle:

```sh
kubectl -n infoblox-webhook create configmap infoblox-ca \
  --from-file=ca.crt=/secure/path/infoblox-ca-chain.pem
```

The WAPI server must present a certificate valid for the configured hostname.
The webhook's Kubernetes serving certificate is separate and is managed by the
chart's cert-manager Certificate resources.

### 3. Configure Helm

Create `values-production.yaml`:

```yaml
groupName: acme.example.com
infoblox:
  host: infoblox.example.com
  port: 443
  version: "2.10" # Choose a version supported by your GRID.
  credentials:
    existingSecret: infoblox-credentials
    key: creds.json
  tls:
    verify: true
    caBundle:
      existingConfigMap: infoblox-ca
      key: ca.crt
image:
  # Published OCI charts already pin their corresponding image digest.
  # Override repository/digest only when deploying your own build.
  pullPolicy: IfNotPresent
```

For a publicly trusted WAPI certificate, omit `caBundle.existingConfigMap`.
Choose a published fork chart version, then install it directly from GHCR:

```sh
export CHART_VERSION=X.Y.Z # Replace with an actual published chart version.
helm upgrade --install infoblox-webhook \
  oci://ghcr.io/balex42/charts/cert-manager-webhook-infoblox-wapi \
  --version "$CHART_VERSION" \
  --namespace infoblox-webhook \
  --values values-production.yaml \
  --wait --timeout 5m
kubectl wait --for=condition=Available \
  apiservice/v1alpha1.acme.example.com --timeout=3m
```

The public chart package is
`ghcr.io/balex42/charts/cert-manager-webhook-infoblox-wapi`. OCI installation does
not require `helm repo add`. A published chart contains its release image digest;
the source chart uses appVersion/tag until packaged by the release workflow.

For local development, install `./charts/cert-manager-webhook-infoblox-wapi` and
explicitly set the image repository and digest (or tag) for the image you built.

### 4. Create a ClusterIssuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    email: admin@example.com
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-staging-account
    solvers:
      - dns01:
          webhook:
            groupName: acme.example.com
            solverName: infoblox-wapi
            config:
              view: External
              ttl: 300
              useTtl: true
```

Only `view`, `ttl`, and `useTtl` are accepted in solver config. `view` is required;
TTL defaults to 300 seconds and `useTtl` defaults to true. Explicit false is
preserved. TTL zero uses the default.

Certificates in different application namespaces can reference this ClusterIssuer.
Choose the DNS view that serves the challenge records. cert-manager's DNS self-check
and the ACME server must both be able to resolve them. For split-horizon setups,
check authoritative visibility and cert-manager's recursive DNS configuration.

## Helm settings

See [values.yaml](charts/cert-manager-webhook-infoblox-wapi/values.yaml) and its
JSON schema for the complete chart settings. Important values:

| Setting | Default | Purpose |
| --- | --- | --- |
| `infoblox.host` | Required | WAPI hostname or IPv4 address, without scheme/port/path |
| `infoblox.port` | `443` | WAPI HTTPS port |
| `infoblox.version` | `"2.10"` | WAPI API version |
| `infoblox.credentials.existingSecret` | `infoblox-credentials` | Secret in release namespace |
| `infoblox.credentials.key` | `creds.json` | Secret key mapped to the fixed credentials path |
| `infoblox.tls.verify` | `true` | Certificate and hostname verification |
| `infoblox.tls.caBundle.existingConfigMap` | Empty | Optional internal CA ConfigMap |
| `infoblox.tls.caBundle.key` | `ca.crt` | ConfigMap key mapped to the fixed CA path |
| `infoblox.httpRequestTimeout` | `60` | Per-request timeout in seconds |
| `infoblox.httpPoolConnections` | `10` | Maximum idle connections per WAPI host |
| `securePort` | `8443` | Non-privileged webhook listener |
| `service.port` | `443` | Kubernetes Service port |
| `image.digest` | Empty | Immutable image digest, taking precedence over tag |
| `networkPolicy.enabled` | `false` | Enable explicit network restrictions |

`infoblox.tls.verify: false` is an explicit deployment-level opt-out. It cannot
be combined with a configured CA bundle. Trusting the internal CA is preferred.

### NetworkPolicy

When enabled, configure `networkPolicy.ingressPeers` for API-server traffic and
`networkPolicy.egressRules` for WAPI and Kubernetes API destinations. These are
required: API servers may be external or host-networked and cannot reliably be
identified by namespace selectors. Account for your CNI's Service NAT behavior.

`networkPolicy.dnsPeers` defaults to kube-dns-labeled pods in `kube-system` on
TCP/UDP 53. Adjust it for NodeLocal DNS or other resolver deployments. See
[tests/chart-values.yaml](tests/chart-values.yaml) for the configuration shape;
its IPs are documentation examples.

## Migration from upstream

This is a breaking configuration change:

1. Convert credential references or a node-local file into an existing Secret
   containing a JSON `creds.json` object in the webhook namespace.
2. Replace `secretVolume.hostPath` with `infoblox.credentials.existingSecret`.
3. Move host, port, WAPI version, HTTP options, and TLS settings from solver config
   into Helm's `infoblox` settings. Remove `usernameSecretRef`,
   `passwordSecretRef`, `getUserFromVolume`, and `sslVerify` from solver config.
4. Keep only DNS view and TTL settings in the Issuer. Unknown keys are rejected.
5. Supply the internal CA bundle before enabling verification against private PKI.
6. Use an authorized ClusterIssuer and check ambient-credential configuration.
7. Roll out the new chart and fork image together. Verify the APIService and a
   staging issuance before switching production certificates.

The chart retains upstream's release version until the next versioned release;
the existing version does not imply an image containing these changes is published.

## Development and verification

```sh
make test
make test-race
go vet ./...
helm lint charts/cert-manager-webhook-infoblox-wapi \
  --set infoblox.host=infoblox.example.com --strict
go test -tags=chart -run TestChartConfiguration .
python3 -m unittest discover -s tests -p 'test_release*.py' -v
```

Tests exercise the real Infoblox connector against a local HTTPS WAPI stub. They
cover concurrent TXT values, retry idempotency, cleanup isolation, credential
rotation, TLS trust, hostname verification, and response redaction. Chart tests
check mounts, ports, immutable images, private CAs, and invalid configurations.

The Helm workflow installs the chart in Kind, waits for the webhook and APIService,
and checks that its service account cannot read credentials Secrets in the webhook
or application namespaces. Live provider conformance and actual multi-namespace
issuance still require a configured Infoblox and ACME environment; see
[docs/TESTING.md](docs/TESTING.md).

## Images, releases, and licensing

The release workflow validates the tagged revision through CI and Kind tests,
then builds `linux/amd64` and `linux/arm64` images with SBOM/provenance attestations.
It signs the image digest, uploads a Trivy vulnerability/license report, and
publishes a separate OCI Helm chart pinned to that digest. The chart is pulled
back, compared with the release package, rendered, and signed by its OCI digest.
Retries reuse matching existing artifacts and reject conflicting versions. See
[workflow setup](.github/workflows/README.md) for publishing credentials and
verification commands. Dependency metadata and the final SBOM should be reviewed
when distributing images; compiled Go dependencies retain their own licenses.

The project is Apache-2.0 licensed. Preserve [LICENSE](LICENSE), [NOTICE](NOTICE),
and applicable attributions. Both files are included under `/licenses` in the image.
Chainguard base packages retain their respective licenses and distribution terms.

### Attribution

Originally developed by Luis Gracia while at The Rockefeller University, based on
[cert-manager/webhook-example](https://github.com/cert-manager/webhook-example),
then maintained and extended by [Dave Sargent](https://github.com/sarg3nt).
Shared-account, TLS, deployment, test, and image hardening modifications are by
the [balex42 fork](https://github.com/balex42/cert-manager-webhook-infoblox-wapi).
Historical changes and attribution remain in [CHANGELOG.md](CHANGELOG.md) and NOTICE.
