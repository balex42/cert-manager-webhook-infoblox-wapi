# Testing the shared-account webhook

Modified for the balex42 fork. Unit tests require the Go version in `go.mod`.
Race tests also need a C compiler and CGO enabled.

## Local regression tests

```sh
make test
make test-race
make test-coverage
go vet ./...
go test -tags=chart -run TestChartConfiguration . # Requires helm in PATH.
python3 -m unittest discover -s tests -p 'test_release*.py' -v
```

Unit tests contact only local HTTPS WAPI stubs. They exercise actual connector
serialization and filtering, repeated and concurrent calls, isolated cleanup,
credential rotation, error propagation, and TLS failure behavior. They do not
require Kubernetes, a real GRID, or public DNS. Helm tests verify the rendered
deployment contract and schema failures.

Release-tool tests use Python's standard library. Set `OCI_TEST_REGISTRY` to a
disposable local Registry v2 instance (for example, `127.0.0.1:5000`) to also test
real Helm OCI push/pull, retry preservation, and rejection of conflicting image
digests for the same chart version. This test deliberately uses plain HTTP for
the local registry; production publishing uses HTTPS. The Helm CI workflow runs
this round-trip against its own registry service.

## Kubernetes deployment/RBAC checks

The Helm workflow loads the fork image into Kind and installs cert-manager and
the chart. It supplies a test credentials Secret, requires serving Certificates,
Deployment and APIService readiness, runs the chart health test, and checks that
the webhook cannot read Secrets through Kubernetes in three namespaces.

WAPI is not contacted at startup. Readiness establishes API availability, not
reachability of Infoblox or successful issuance.

## Live Infoblox conformance

Use a dedicated DNS test zone, a least-privileged Infoblox account, and a WAPI
version supported by the test GRID. Mount credentials as `/etc/secrets/creds.json`
in the test runner and, for private PKI, mount the CA bundle. Both files contain
ordinary JSON/PEM, not individually base64-encoded values.

Copy `testdata/infoblox-wapi/config.json.sample` to `config.json` and set the
actual DNS view. Export the deployment settings:

```sh
export INFOBLOX_HOST=infoblox.example.com
export INFOBLOX_PORT=443
export INFOBLOX_VERSION=2.10
export INFOBLOX_CA_FILE=/etc/infoblox-ca/ca.crt
export TEST_ZONE_NAME=acme-test.example.com.
make test-integration
```

Omit `INFOBLOX_CA_FILE` when system trust suffices. The fixture enables ambient
credentials to match the shared-account design. The integration build tag and
`TEST_ZONE_NAME` are required; a skipped test is not conformance evidence.
The integration target downloads envtest assets for the cert-manager fixture.

## End-to-end acceptance in your cluster

After deploying the fork with internal CA verification enabled:

1. Create one staging ClusterIssuer using the webhook and two application namespaces.
2. Request a Certificate with both `example.com` and `*.example.com` in namespace A,
   using domains delegated to the test GRID and visible to the ACME test server.
3. Request an overlapping Certificate in namespace B while A is issuing.
4. Observe challenge TXT records in the configured DNS view and verify issuance.
   cert-manager may serialize challenges for a DNS name; the unit suite separately
   exercises genuinely simultaneous webhook calls.
5. Verify cleanup removed only completed challenge values. Seed an unrelated TXT
   value and an identically named record in another view before the test.
6. Rotate the mounted credentials; after Secret projection, repeat issuance.
7. Update the CA ConfigMap to the intended replacement chain and repeat issuance.
   An invalid bundle must fail operations, never disable verification.
8. Confirm the webhook's service account has no Secret-reading access in either
   application namespace or the webhook namespace.

For split-horizon DNS, verify both cert-manager self-check and ACME authoritative
visibility. Record the cluster, cert-manager/GRID versions, image digest, zone/view,
and test result when collecting production-readiness evidence.
