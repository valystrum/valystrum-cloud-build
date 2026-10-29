# Changelog

Each release is a tag of this repository. Copy the scripts of the release you want into `.valystrum/` (see the
README's Quick start); to update, copy them again from a newer release.

## v1.0.0 (2026-10-29)

The first release, for Valystrum v0.21.0 and later.

- `valystrum-scan.sh` with `examples/cloudbuild-security-scan.yaml`: leaked secrets, code analysis (SAST) and IaC
  checks on a pull request's changed files, and the build failed on a critical or high finding.
- `valystrum-sbom.sh` with `examples/cloudbuild-sbom.yaml`: a CycloneDX SBOM made with the official CycloneDX
  generators (pinned, their dependencies locked by hash) and uploaded to your Valystrum software inventory, with
  `VALYSTRUM_COMPLETE` to remove what the SBOM no longer lists.
- The secret comes from Google Secret Manager.
