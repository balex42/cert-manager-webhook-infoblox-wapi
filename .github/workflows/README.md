# Fork CI and OCI releases

Modified for `balex42/cert-manager-webhook-infoblox-wapi`.

## Artifact locations

| Artifact | GHCR package |
| --- | --- |
| Multi-platform image | `ghcr.io/balex42/cert-manager-webhook-infoblox-wapi` |
| Helm OCI chart | `oci://ghcr.io/balex42/charts/cert-manager-webhook-infoblox-wapi` |

## Release flow

1. `release-please.yml` opens a release PR and updates the release manifest,
   chart version, and appVersion together.
2. Merging that PR creates a `vX.Y.Z` tag. `release.yml` checks the tag's exact
   commit and rejects mismatches between tag, chart version, and appVersion.
3. Reusable `ci.yml` and `helm.yml` validate that same commit, including Kind
   APIService/readiness/RBAC checks. Publishing depends on both succeeding.
4. The image job publishes amd64/arm64 images with SBOM/provenance, signs the
   image index digest, and uploads a Trivy vulnerability/license report.
5. `release-chart.yml`, called only after the image job succeeds, stages the
   source chart with the published image repository and immutable image digest.
   It includes LICENSE/NOTICE, packages and pushes to GHCR with native Helm OCI
   support, pulls back by digest, compares package contents, renders, and signs.

The image version tag is reused on retry only if both platform images identify
the same source repository, release commit, and version. Existing chart versions
are pulled and compared; conflicting contents are rejected rather than overwritten.
Registry authentication/network failures are not treated as missing artifacts.

The manual **Release** workflow input is an existing release tag, not a branch.
Use it to recover a partial publication. The release summary contains both
artifact digests and an installation command.

`release-monthly.yml` opens a small monthly refresh PR. After review and merge,
Release Please requests a patch release through the same flow. It does not invent
another version or publish an independently versioned image. Dependabot maintains
pinned base images, modules, and actions; a scheduled refresh alone does not update
those pins.

## One-time GitHub setup

1. Enable Actions for the fork.
2. Set the repository secret `GH_TOKEN` for Release Please and monthly refresh PRs.
   It must have access to this repository's contents and pull requests. A PAT or
   equivalent automation token is needed so generated PRs and tags trigger CI and
   the release workflow. It is never an Infoblox credential.
3. Image/chart publishing uses the automatic `GITHUB_TOKEN` with job-scoped
   `packages: write`; signing uses job-scoped `id-token: write`. If a package
   already exists, grant this repository Actions access to it in GHCR settings.
4. After first publication, set **both GHCR packages to Public** in their package
   settings so anonymous image/chart pulls work. New GHCR packages may start private
   even when the GitHub repository is public. Link the chart package to this source
   repository if GHCR has not automatically associated it.
5. Check the first hosted CI and versioned release runs. Local validation cannot
   prove registry permissions or GitHub OIDC signing.

GitHub Pages and a `gh-pages` branch are not part of this publishing setup.
For this breaking configuration migration, use a breaking-change Conventional
Commit when preparing the first release PR so Release Please selects an appropriate
major version. An inherited upstream tag does not imply fork artifacts exist.

## Install the public chart

```sh
helm upgrade --install infoblox-webhook \
  oci://ghcr.io/balex42/charts/cert-manager-webhook-infoblox-wapi \
  --version X.Y.Z \
  --namespace infoblox-webhook --create-namespace \
  --values values-production.yaml
```

The published chart supplies its matching image digest by default. To pin the
chart artifact itself, use the chart digest from the release summary:

```sh
helm upgrade --install infoblox-webhook \
  oci://ghcr.io/balex42/charts/cert-manager-webhook-infoblox-wapi@sha256:CHART_DIGEST \
  --namespace infoblox-webhook --create-namespace \
  --values values-production.yaml
```

## Verify signatures

Replace VERSION and DIGEST with actual values. For tag-triggered releases:

```sh
cosign verify \
  --certificate-identity=https://github.com/balex42/cert-manager-webhook-infoblox-wapi/.github/workflows/release.yml@refs/tags/vVERSION \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/balex42/cert-manager-webhook-infoblox-wapi@sha256:IMAGE_DIGEST

cosign verify \
  --certificate-identity=https://github.com/balex42/cert-manager-webhook-infoblox-wapi/.github/workflows/release-chart.yml@refs/tags/vVERSION \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/balex42/charts/cert-manager-webhook-infoblox-wapi@sha256:CHART_DIGEST
```

Manual runs use the ref selected when dispatching the workflow for their signing
identity (usually `refs/heads/main`), while checkout and metadata validation still
use the explicitly supplied release tag. For a local reusable workflow, GitHub
records the called workflow's identity; verify the identity from that run.
Cosign verification is separate from Helm's GPG-based `--verify` option.

## Checks and maintenance

- `ci.yml`: module tidiness, vet/lint, regression/race tests, Python release-tool
  tests, coverage, and multi-platform image builds.
- `helm.yml`: chart rendering/schema tests, an OCI registry service round-trip
  (publish/pull/retry/conflict), and Kind deployment/namespace/RBAC tests.
- CodeQL, dependency review/submission, Scorecard, ShellCheck, and scheduled Trivy
  workflows retain upstream analysis. Review the Trivy report and dependency
  licenses when distributing images; root Apache licensing does not cover every
  compiled module or base-image package.

Base-image multi-platform digest pins are maintained by Docker Dependabot. Keep
the compiler pin aligned across Dockerfile, go.mod, .mise.toml, and CI. Native
Helm OCI commands are tested with Helm 3.19.0. Live Infoblox conformance still
requires an external environment; see [testing](../../docs/TESTING.md).
