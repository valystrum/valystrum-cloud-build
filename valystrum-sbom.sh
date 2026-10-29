#!/usr/bin/env bash
# Valystrum SBOM for any CI system: a CycloneDX bill of materials made with the official CycloneDX generators and
# uploaded to Valystrum's software inventory, where its components are matched against CVE feeds and licence policy.
# Licensed under the Apache License 2.0.
#
# Valystrum's GitLab CI/CD, Azure Pipelines, AWS CodeBuild and Google Cloud Build integrations all run this same
# script, unchanged. Set everything through the variables below and leave the script as it is, so an update is a
# plain copy of a newer release.
#
# Needs bash, curl and openssl, plus the toolchain of each ecosystem it reads (node and npm, python3, go, mvn). jq is
# fetched when the machine has none (pinned and checked, below).
#
# Settings, all environment variables:
#   VALYSTRUM_INGEST_URL   required: https://app.valystrum.io/api/v1/<org>/sbom/ingest
#   VALYSTRUM_SECRET       required: the repository's CI secret (cs_wh_...), the same one the security scan uses
#   VALYSTRUM_SOURCE       required: the label the components are grouped under. It also picks the CI key, so it must
#                          equal the repository the key was issued for
#   VALYSTRUM_PATH         the directory holding the manifests (default: .); its subdirectories are not searched
#   VALYSTRUM_ECOSYSTEM    auto (default: every generator whose manifest is present), or a space-separated subset of:
#                          npm python go maven
#   VALYSTRUM_ASSET        the name or hostname of the Valystrum asset these components belong to
#   VALYSTRUM_COMPLETE     false (default). true when this SBOM is the whole of the source: the source's components it
#                          no longer lists are removed in Valystrum and their findings resolve
#   VALYSTRUM_ANNOTATIONS  plain (default), or azure for Azure Pipelines log issues, variables and a build summary
#   VALYSTRUM_OUT_DIR      where the outputs go (default: valystrum-reports): sbom.cdx.json, valystrum-sbom.env
#                          (VALYSTRUM_COMPONENTS, VALYSTRUM_REMOVED) and summary.md
#
# Each generator is pinned to its newest release as of 2026-10-28, and so is everything it installs:
#   npm     @cyclonedx/cyclonedx-npm and its whole tree from a lock file (npm ci), each package by its SHA-512
#   python  cyclonedx-bom (cyclonedx-py) and its whole tree from a hashed requirements file (pip --require-hashes)
#   go      cyclonedx-gomod: `go run module@version` builds from the module's own go.sum, every module checked against
#           Go's checksum database (sum.golang.org)
#   maven   cyclonedx-maven-plugin: its version fixes every dependency's, each checked against the repository's
#           checksums (--strict-checksums)
set -euo pipefail

CDX_NPM_VERSION="6.0.1"
CDX_PY_VERSION="7.6.0"
CDX_GOMOD_VERSION="1.12.0"
CDX_MAVEN_VERSION="2.9.3"

INGEST_URL="${VALYSTRUM_INGEST_URL:-}"
INGEST_SECRET="${VALYSTRUM_SECRET:-}"
SOURCE="${VALYSTRUM_SOURCE:-}"
SCAN_PATH="${VALYSTRUM_PATH:-.}"
ECOSYSTEM="${VALYSTRUM_ECOSYSTEM:-auto}"
ASSET="${VALYSTRUM_ASSET:-}"
COMPLETE="${VALYSTRUM_COMPLETE:-false}"
ANNOTATIONS="${VALYSTRUM_ANNOTATIONS:-plain}"

say_error() { if [ "$ANNOTATIONS" = "azure" ]; then echo "##vso[task.logissue type=error]$1"; else echo "ERROR: $1"; fi; }

[ -n "$INGEST_URL" ] || { say_error "VALYSTRUM_INGEST_URL is empty: set it to https://app.valystrum.io/api/v1/<org>/sbom/ingest."; exit 1; }
[ -n "$INGEST_SECRET" ] || { say_error "VALYSTRUM_SECRET is empty: the pipeline could not read the repository's CI secret (check its name, and that this run may read it)."; exit 1; }
[ -n "$SOURCE" ] || { say_error "VALYSTRUM_SOURCE is empty: set it to the repository as its CI key in Valystrum names it."; exit 1; }

OUT_DIR="${VALYSTRUM_OUT_DIR:-valystrum-reports}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
SUMMARY="$OUT_DIR/summary.md"

# An SBOM upload fails loudly: a rejected or empty upload must not pass as a silent success.
setup_failed() { say_error "$1"; exit 1; }

# ── jq ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
# The one tool most CI images lack: fetched once when there is none, pinned by version and checked by SHA-256.
JQ_VERSION="1.8.2"
if ! command -v jq >/dev/null 2>&1; then
  case "$(uname -m)" in
    x86_64 | amd64) JQ_ASSET="jq-linux-amd64"; JQ_SHA256="b1c22172dd303f3be49e935aa56aa48a8b7a46e0bc838b4997d3bb451495870f" ;;
    aarch64 | arm64) JQ_ASSET="jq-linux-arm64"; JQ_SHA256="8b85c817833814ddca00a144c33705546355afccf0cf39b188f3cdb48b852309" ;;
    *) JQ_ASSET=""; JQ_SHA256="" ;;
  esac
  if [ -z "$JQ_ASSET" ] \
    || ! curl -fsSL --retry 3 -o "$TMP_DIR/jq" "https://github.com/jqlang/jq/releases/download/jq-$JQ_VERSION/$JQ_ASSET" \
    || [ "$(openssl dgst -sha256 -r "$TMP_DIR/jq" | cut -d ' ' -f 1)" != "$JQ_SHA256" ]; then
    setup_failed "jq is not installed, and jq $JQ_VERSION could not be fetched and checked for this machine: install jq in the image."
  fi
  chmod +x "$TMP_DIR/jq"
  PATH="$TMP_DIR:$PATH"
fi

# ── Generate ───────────────────────────────────────────────────────────────────────────────────────────────────────
BOM_DIR="$TMP_DIR/boms"
TOOLS="$TMP_DIR/tools"
mkdir -p "$BOM_DIR" "$TOOLS/npm"

# ── The generators' lock files ─────────────────────────────────────────────────────────────────────────────────────
# Every package the npm and Python generators install, by version and hash, as each release of this script locks
# them: never edit them here.
cat > "$TOOLS/npm/package.json" <<'VALYSTRUM_NPM_PACKAGE'
{
  "name": "valystrum-cyclonedx-npm",
  "private": true,
  "description": "The CycloneDX npm generator the Valystrum SBOM integrations run, every package locked by version and hash.",
  "license": "Apache-2.0",
  "dependencies": {
    "@cyclonedx/cyclonedx-npm": "6.0.1"
  }
}
VALYSTRUM_NPM_PACKAGE
cat > "$TOOLS/npm/package-lock.json" <<'VALYSTRUM_NPM_LOCK'
{"name":"valystrum-cyclonedx-npm","lockfileVersion":3,"requires":true,"packages":{
"":{"name":"valystrum-cyclonedx-npm","license":"Apache-2.0","dependencies":{"@cyclonedx/cyclonedx-npm":"6.0.1"}},
"node_modules/@cyclonedx/cyclonedx-library":{"version":"10.3.0","resolved":"https://registry.npmjs.org/@cyclonedx/cyclonedx-library/-/cyclonedx-library-10.3.0.tgz","integrity":"sha512-RIT28sp1U0PCHaaeF3yNRwk6Jig/XJ8UsYAVOMYaHQ+0VVOvsjcp0PTWQFLUqJFF8XMud+Kdq6G+wtDAh+QJFA==","funding":[{"type":"individual","url":"https://owasp.org/donate/?reponame=www-project-cyclonedx&title=OWASP+CycloneDX"}],"license":"Apache-2.0","engines":{"node":">=20.18.0"},"peerDependencies":{}},
"node_modules/@cyclonedx/cyclonedx-npm":{"version":"6.0.1","resolved":"https://registry.npmjs.org/@cyclonedx/cyclonedx-npm/-/cyclonedx-npm-6.0.1.tgz","integrity":"sha512-/aU3bBC6qP6cV/qQ5SfUSygE/+2hQhwgg6sJML31/gZ96NyMvIUuwdk637H4z+LS/NryRT2kjR2wtD0qBEVVHQ==","funding":[{"type":"individual","url":"https://owasp.org/donate/?reponame=www-project-cyclonedx&title=OWASP+CycloneDX"}],"license":"Apache-2.0","dependencies":{"@cyclonedx/cyclonedx-library":"^10.0.0","commander":"^14.0.0","normalize-package-data":"^7.0.0 || ^8.0.0","packageurl-js":"^2.0.1","spdx-expression-parse":"^3.0.1 || ^4.0.0","xmlbuilder2":"^3.0.2 || ^4.0.3"},"bin":{"cyclonedx-npm":"bin/cyclonedx-npm-cli.js"},"engines":{"node":">=20.18.0","npm":">=9"}},
"node_modules/@oozcitak/dom":{"version":"2.0.2","resolved":"https://registry.npmjs.org/@oozcitak/dom/-/dom-2.0.2.tgz","integrity":"sha512-GjpKhkSYC3Mj4+lfwEyI1dqnsKTgwGy48ytZEhm4A/xnH/8z9M3ZVXKr/YGQi3uCLs1AEBS+x5T2JPiueEDW8w==","license":"MIT","dependencies":{"@oozcitak/infra":"^2.0.2","@oozcitak/url":"^3.0.0","@oozcitak/util":"^10.0.0"},"engines":{"node":">=20.0"}},
"node_modules/@oozcitak/infra":{"version":"2.0.2","resolved":"https://registry.npmjs.org/@oozcitak/infra/-/infra-2.0.2.tgz","integrity":"sha512-2g+E7hoE2dgCz/APPOEK5s3rMhJvNxSMBrP+U+j1OWsIbtSpWxxlUjq1lU8RIsFJNYv7NMlnVsCuHcUzJW+8vA==","license":"MIT","dependencies":{"@oozcitak/util":"^10.0.0"},"engines":{"node":">=20.0"}},
"node_modules/@oozcitak/url":{"version":"3.0.0","resolved":"https://registry.npmjs.org/@oozcitak/url/-/url-3.0.0.tgz","integrity":"sha512-ZKfET8Ak1wsLAiLWNfFkZc/BraDccuTJKR6svTYc7sVjbR+Iu0vtXdiDMY4o6jaFl5TW2TlS7jbLl4VovtAJWQ==","license":"MIT","dependencies":{"@oozcitak/infra":"^2.0.2","@oozcitak/util":"^10.0.0"},"engines":{"node":">=20.0"}},
"node_modules/@oozcitak/util":{"version":"10.0.0","resolved":"https://registry.npmjs.org/@oozcitak/util/-/util-10.0.0.tgz","integrity":"sha512-hAX0pT/73190NLqBPPWSdBVGtbY6VOhWYK3qqHqtXQ1gK7kS2yz4+ivsN07hpJ6I3aeMtKP6J6npsEKOAzuTLA==","license":"MIT","engines":{"node":">=20.0"}},
"node_modules/argparse":{"version":"2.0.1","resolved":"https://registry.npmjs.org/argparse/-/argparse-2.0.1.tgz","integrity":"sha512-8+9WqebbFzpX9OR+Wa6O29asIogeRMzcGtAINdpMHHyAg10f05aSFVBbcEqGf/PXw1EjAZ+q2/bEBg3DvurK3Q==","license":"Python-2.0"},
"node_modules/commander":{"version":"14.0.3","resolved":"https://registry.npmjs.org/commander/-/commander-14.0.3.tgz","integrity":"sha512-H+y0Jo/T1RZ9qPP4Eh1pkcQcLRglraJaSLoyOtHxu6AapkjWVCy2Sit1QQ4x3Dng8qDlSsZEet7g5Pq06MvTgw==","license":"MIT","engines":{"node":">=20"}},
"node_modules/hosted-git-info":{"version":"9.0.3","resolved":"https://registry.npmjs.org/hosted-git-info/-/hosted-git-info-9.0.3.tgz","integrity":"sha512-Hc+ghLoSt6QaYZUv0WBiIvmMDZuZZ7oaDvdH8MbfOO4lOsxdXLEvuC6ePoGs9H1X9oCLyq6+NVN0MKqD+ydxyg==","license":"ISC","dependencies":{"lru-cache":"^11.1.0"},"engines":{"node":"^20.17.0 || >=22.9.0"}},
"node_modules/hosted-git-info/node_modules/lru-cache":{"version":"11.5.3","resolved":"https://registry.npmjs.org/lru-cache/-/lru-cache-11.5.3.tgz","integrity":"sha512-U4N8FgzmWxc8k1VH8Kr6lQg18U7Fjvby6wXHVRX/ZZ7IwWbRMgrRbP0Wrb5q5NVinryp4SQampHKdvtecItxUg==","license":"BlueOak-1.0.0","engines":{"node":"20 || >=22"}},
"node_modules/js-yaml":{"version":"4.3.2","resolved":"https://registry.npmjs.org/js-yaml/-/js-yaml-4.3.2.tgz","integrity":"sha512-SFNOvSJ+Dgf/9An904Yx+CgSlIPCkIpao4qo51lpee25TIRejdH3rhR4EZMGoNx3/TP3O+wzWuiTFl4sqbltzA==","funding":[{"type":"github","url":"https://github.com/sponsors/puzrin"},{"type":"github","url":"https://github.com/sponsors/nodeca"}],"license":"MIT","dependencies":{"argparse":"^2.0.1"},"bin":{"js-yaml":"bin/js-yaml.js"}},
"node_modules/normalize-package-data":{"version":"8.0.0","resolved":"https://registry.npmjs.org/normalize-package-data/-/normalize-package-data-8.0.0.tgz","integrity":"sha512-RWk+PI433eESQ7ounYxIp67CYuVsS1uYSonX3kA6ps/3LWfjVQa/ptEg6Y3T6uAMq1mWpX9PQ+qx+QaHpsc7gQ==","license":"BSD-2-Clause","dependencies":{"hosted-git-info":"^9.0.0","semver":"^7.3.5","validate-npm-package-license":"^3.0.4"},"engines":{"node":"^20.17.0 || >=22.9.0"}},
"node_modules/packageurl-js":{"version":"2.0.1","resolved":"https://registry.npmjs.org/packageurl-js/-/packageurl-js-2.0.1.tgz","integrity":"sha512-N5ixXjzTy4QDQH0Q9YFjqIWd6zH6936Djpl2m9QNFmDv5Fum8q8BjkpAcHNMzOFE0IwQrFhJWex3AN6kS0OSwg==","license":"MIT"},
"node_modules/semver":{"version":"7.8.5","resolved":"https://registry.npmjs.org/semver/-/semver-7.8.5.tgz","integrity":"sha512-Y7/KDsb8LjooZpwaqGyulO6DQlksgCncchHGk+sZIY4SBvUocMBEFH5Ur1fI4dV+Jvl0w6cjvucaIi40puRioA==","license":"ISC","bin":{"semver":"bin/semver.js"},"engines":{"node":">=10"}},
"node_modules/spdx-correct":{"version":"3.2.0","resolved":"https://registry.npmjs.org/spdx-correct/-/spdx-correct-3.2.0.tgz","integrity":"sha512-kN9dJbvnySHULIluDHy32WHRUu3Og7B9sbY7tsFLctQkIqnMh3hErYgdMjTYuqmcXX+lK5T1lnUt3G7zNswmZA==","license":"Apache-2.0","dependencies":{"spdx-expression-parse":"^3.0.0","spdx-license-ids":"^3.0.0"}},
"node_modules/spdx-correct/node_modules/spdx-expression-parse":{"version":"3.0.1","resolved":"https://registry.npmjs.org/spdx-expression-parse/-/spdx-expression-parse-3.0.1.tgz","integrity":"sha512-cbqHunsQWnJNE6KhVSMsMeH5H/L9EpymbzqTQ3uLwNCLZ1Q481oWaofqH7nO6V07xlXwY6PhQdQ2IedWx/ZK4Q==","license":"MIT","dependencies":{"spdx-exceptions":"^2.1.0","spdx-license-ids":"^3.0.0"}},
"node_modules/spdx-exceptions":{"version":"2.5.0","resolved":"https://registry.npmjs.org/spdx-exceptions/-/spdx-exceptions-2.5.0.tgz","integrity":"sha512-PiU42r+xO4UbUS1buo3LPJkjlO7430Xn5SVAhdpzzsPHsjbYVflnnFdATgabnLude+Cqu25p6N+g2lw/PFsa4w==","license":"CC-BY-3.0"},
"node_modules/spdx-expression-parse":{"version":"4.0.0","resolved":"https://registry.npmjs.org/spdx-expression-parse/-/spdx-expression-parse-4.0.0.tgz","integrity":"sha512-Clya5JIij/7C6bRR22+tnGXbc4VKlibKSVj2iHvVeX5iMW7s1SIQlqu699JkODJJIhh/pUu8L0/VLh8xflD+LQ==","license":"MIT","dependencies":{"spdx-exceptions":"^2.1.0","spdx-license-ids":"^3.0.0"}},
"node_modules/spdx-license-ids":{"version":"3.0.24","resolved":"https://registry.npmjs.org/spdx-license-ids/-/spdx-license-ids-3.0.24.tgz","integrity":"sha512-cLS9TtWkIQFyLkJ3/5aFQAOHOSKTlOs/7WDut/XPSdjom1fJhUdkepeJAKXa9Y05+FabHd0sti+Et559vDtkpQ==","license":"CC0-1.0"},
"node_modules/validate-npm-package-license":{"version":"3.0.4","resolved":"https://registry.npmjs.org/validate-npm-package-license/-/validate-npm-package-license-3.0.4.tgz","integrity":"sha512-DpKm2Ui/xN7/HQKCtpZxoRWBhZ9Z0kqtygG8XCgNQ8ZlDnxuQmWhj566j8fN4Cu3/JmbhsDo7fcAJq4s9h27Ew==","license":"Apache-2.0","dependencies":{"spdx-correct":"^3.0.0","spdx-expression-parse":"^3.0.0"}},
"node_modules/validate-npm-package-license/node_modules/spdx-expression-parse":{"version":"3.0.1","resolved":"https://registry.npmjs.org/spdx-expression-parse/-/spdx-expression-parse-3.0.1.tgz","integrity":"sha512-cbqHunsQWnJNE6KhVSMsMeH5H/L9EpymbzqTQ3uLwNCLZ1Q481oWaofqH7nO6V07xlXwY6PhQdQ2IedWx/ZK4Q==","license":"MIT","dependencies":{"spdx-exceptions":"^2.1.0","spdx-license-ids":"^3.0.0"}},
"node_modules/xmlbuilder2":{"version":"4.0.3","resolved":"https://registry.npmjs.org/xmlbuilder2/-/xmlbuilder2-4.0.3.tgz","integrity":"sha512-bx8Q1STctnNaaDymWnkfQLKofs0mGNN7rLLapJlGuV3VlvegD7Ls4ggMjE3aUSWItCCzU0PEv45lI87iSigiCA==","license":"MIT","dependencies":{"@oozcitak/dom":"^2.0.2","@oozcitak/infra":"^2.0.2","@oozcitak/util":"^10.0.0","js-yaml":"^4.1.1"},"engines":{"node":">=20.0"}}
}}
VALYSTRUM_NPM_LOCK
cat > "$TOOLS/cyclonedx-bom.txt" <<'VALYSTRUM_PY_LOCK'
# The CycloneDX Python generator and its whole dependency tree, by version and by the SHA-256 of every wheel a Linux
# runner's CPython 3.9 or later installs (x86_64 and aarch64). Installed with pip --require-hashes --no-deps
# --only-binary=:all:. Generated for each release of the Valystrum SBOM integrations; do not edit by hand.
arrow==1.4.0 \
    --hash=sha256:749f0769958ebdc79c173ff0b0670d59051a535fa26e8eba02953dc19eb43205
attrs==26.1.0 \
    --hash=sha256:c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309
boolean-py==5.0 \
    --hash=sha256:ef28a70bd43115208441b53a045d1549e2f0ec6e3d08a9d142cbc41c1938e8d9
chardet==5.2.0 ; python_full_version < '3.10' \
    --hash=sha256:e1cf59446890a00105fe7b7912492ea04b6e6f06d4b742b2c788469e34c82970
chardet==7.7.0 ; python_full_version >= '3.10' \
    --hash=sha256:091f50d3567b1a066f797835ee5367dbcf3cb77c5e56993b3f61b28264b8e6f8 \
    --hash=sha256:11cf9b719ea3675a2a7d8a3071bbe4d7ea24b26bfe39a51588d515ddd05cacad \
    --hash=sha256:1292aedb9e9da26435f7972f7efa145e773140068238888c6a533c1b5f17b88b \
    --hash=sha256:2a990ca38150936cc8f63d66f360ba8c50310632f159ef482008f033185fb004 \
    --hash=sha256:42c4d8a2dc8abcc067417adc13c2f64f48482e48ce48e3af769b5a44214e5a5c \
    --hash=sha256:56e5a5c782548b301b44371de327115d13a08de391ddaf9db4ac420d8511c5d7 \
    --hash=sha256:68db376d4bb403dc282a6d2ed5b4c4b45a7a21dc7537e79699f8be669a9e88ef \
    --hash=sha256:79eec5af9d7715334695254234c8d7c29165841526c11083951d9b9f6458e372 \
    --hash=sha256:7f13de78af5da07ddd813ff5a564c3aa8a113f05cba202be649e061c431a0e9a \
    --hash=sha256:80db1c109e6e3c102ac589897449437ea2edf26dda1042a3ff669368e21d90e5 \
    --hash=sha256:a05667635c0496dab47eca8c845c044d1da6d74d34a9bf687199c9c53a38119d \
    --hash=sha256:a76f4d1f769b4ae8888cefd46e604cf1f5769f1176b55e78b90eaeefa888ce92 \
    --hash=sha256:c519c10c315a675bcfd4b55c0e0de1859ca5a39881d8f69750500102c2fc5d2f \
    --hash=sha256:d227d2aa329fcf848f4640ed9a4d99e1753840c1cfa19f7ca5a48f30c03982ad \
    --hash=sha256:ddedfb252d05c86c2d6e9a3090f8bd574876bbd39679e7c588ed57d21595c097 \
    --hash=sha256:f8783b6e24a044ed9b53aa130ffafac4286aaf4a953f7843a3c1a261d7c77971 \
    --hash=sha256:feb66c96264e3e6a9ff0c7318ce0028800b6c18ad07c8000d2404a108d1ef767
cyclonedx-bom==7.6.0 \
    --hash=sha256:4db70eb524e859317c645bbe927347e18bdd3cfa31906b1e482b4b936f8c36ef
cyclonedx-python-lib==11.12.0 \
    --hash=sha256:0e807521a921a5c3cb8ce1153f8a61d29eedfe76a46aac2796b7c6b573391a54
defusedxml==0.7.1 \
    --hash=sha256:a352e7e428770286cc899e2542b6cdaedb2b4953ff269a210103ec58f6198a61
fqdn==1.6.0 \
    --hash=sha256:6c793c312ccfa29981e1135b3ef5e1277ebe639731a6b0f7350d90e96e63f0b4
idna==3.20 \
    --hash=sha256:ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c
isoduration==20.11.0 \
    --hash=sha256:b2904c2a4228c3d44f409c8ae8e2370eb21a26f7ac2ec5446df141dde3452042
jsonpointer==3.0.0 ; python_full_version < '3.10' \
    --hash=sha256:13e088adc14fca8b6aa8177c044e12701e6ad4b28ff10e65f2267a90109c9942
jsonpointer==3.6 ; python_full_version >= '3.10' \
    --hash=sha256:a45c858f8a9e171f6b3790ed9446c9382782f6c4cb4589176813c5a553f4cfcd
jsonschema==4.25.1 ; python_full_version < '3.10' \
    --hash=sha256:3fba0169e345c7175110351d456342c364814cfcf3b964ba4587f22915230a63
jsonschema==4.26.0 ; python_full_version >= '3.10' \
    --hash=sha256:d489f15263b8d200f8387e64b4c3a75f06629559fb73deb8fdfb525f2dab50ce
jsonschema-specifications==2025.9.1 \
    --hash=sha256:98802fee3a11ee76ecaca44429fda8a41bff98b00a0f2838151b113f210cc6fe
lark==1.3.1 \
    --hash=sha256:c629b661023a014c37da873b4ff58a817398d12635d3bbb2c5a03be7fe5d1e12
license-expression==30.4.4 \
    --hash=sha256:421788fdcadb41f049d2dc934ce666626265aeccefddd25e162a26f23bcbf8a4
lxml==6.1.3 \
    --hash=sha256:0f17d83c48ee9dfd96abae3ac3e2108c76d2fc86ce96355e37b8da9f7f4ecc08 \
    --hash=sha256:16148acd77ed1d8836a56db883af2f5eed720f9723088110b16a0d08582130a6 \
    --hash=sha256:170773d8a3cdc76259065523ddd978c44f9806e28605f08812e8f86783e44ac6 \
    --hash=sha256:207dfc3d47cf0e575e643bbc140dacc8863b39abaa1e5307cd64c7f2365b8a12 \
    --hash=sha256:2221e88679d1351e9a40aaee54bc65679b9795bbd0160bc3d5e36b163344eb75 \
    --hash=sha256:28a23fefdb345b2d4d0ff2860571b5ff9a89a28b6a120f720e8fb0324d346626 \
    --hash=sha256:2cae5d5c90a62d9139c512a0cb1aad1d182b022b5740daea2617eb5bf7fc658e \
    --hash=sha256:2e01125896585139453cab8cb235893644d8815d7509520da95ae3ee8d1c1f79 \
    --hash=sha256:2f5b2a2b9811b853b39bfa41367c6d78747b8e3e80e07fc5a24aae295c1a4d7d \
    --hash=sha256:302f72413251c03f671e063c9414bed5dc8c927069e5abb69245521e51a4e81b \
    --hash=sha256:379f8a75cf6eb7eef0af074b55f49ab73b868388a98de14646abcdfa4564bb11 \
    --hash=sha256:38fc4e4e4e084e0bd491949482527d406788045c546d4f8789e93fc527b91385 \
    --hash=sha256:40983eabefd13da003e68170928c7acc011f0d095eefce5871a3c71c9385fb9a \
    --hash=sha256:41e2d428110b408e963b6fb18f9bbf1f5c027b56bd4b498d54556476c0aeb1c3 \
    --hash=sha256:49fbc2682a9306135b7ec49e93f97f9c26689b9b7f96ed2742d8d6497e994d13 \
    --hash=sha256:4a579dfb9c835f8ab47f4b8ed33440cbc75b806b73297208e6ec2a33e903740b \
    --hash=sha256:4e11e885e0704be185867fcf71b904d8f65d7d6877bc121f69870b0d0479ba7b \
    --hash=sha256:527195c188d7d0af748cd48d220ab8cdc5cb99be3d49ac4d9be7324d8abf9bc0 \
    --hash=sha256:545ccc14fb05485f48b4439ec35beb16d5b5280eb6c81c658bd4707a2a119414 \
    --hash=sha256:5cffe18571ccc51d742cd08cbb3f8b756de9311d18c7ea98f5d92f37b8fb60c2 \
    --hash=sha256:5d582042c69857c364e8153de6e18e0da9b7b515a6a8113caf69a6ec8e0520f2 \
    --hash=sha256:61116cec57ed69aebc70f37a545eec095339bb829efbdabcfb97c51e9536e158 \
    --hash=sha256:611a51e61c92f62345a50b0035df6fc0d678f9299f33728826d831598862f59d \
    --hash=sha256:6374e9e382e5a98c9c5e66d41b357b470da1c54bce30f17f9dc4bcc58436cc1c \
    --hash=sha256:69cafd61aea04ebb3502c93c2aaa568b12931ca0802231e0b5de76bf8b6e74bd \
    --hash=sha256:73fc05988ed20809450474ba760a87c8ad4e455fc09783c02195e56ec634b41a \
    --hash=sha256:773062aec2f2e56b2b22d37054123f0de8a22a4688a0c3376c3fe42685f975cf \
    --hash=sha256:83e3a51e7933db700a0da0db31849db3a24022d9970da9bb73001e1d0326fd92 \
    --hash=sha256:8db38ff3fb7aee7d6a82ae4da2eef1178656fe1216841fbd24870062a9d60473 \
    --hash=sha256:909f4e927bb051f7740d6367285fc60cdcfdaf0258c2dba4ff5ba7eadadc250c \
    --hash=sha256:90f709b9accab6b2e4d14f5c8718203877a0486bcb3afd74d8b539ecd1e961d4 \
    --hash=sha256:a1932d7ce78a561367512c594fe66eac2b2ec9b9264cfd9b5f950622f4a116e2 \
    --hash=sha256:a7eb78ba28b187e1e9203a55c60fcf70df2d22cb205fe6d51b9383d6097419f0 \
    --hash=sha256:aa9fd1ee2a5dacfc41039ed49ffeeacfa75bafbd255b69f3b578e11897a0e623 \
    --hash=sha256:b37772102d44bb6628186accca3a121b1fa3a6b3d97518a8c29a5229ca4c0d0a \
    --hash=sha256:b477912f42c5c33405a10c759d22f80cf5af043ae02d95b9d8e5e5bc555739ed \
    --hash=sha256:c00e26288784460885fe76e4d4b293573e0f791f52e6d60e27b42edf005922eb \
    --hash=sha256:c34ca1dc41bd86d9ff830d5bdf4e4a752bba6c54f7d2707027ce0eabd36084c9 \
    --hash=sha256:c55e71a9b1db1f107efb60da49c093689b74c5c31a708e5379e2fd9439d4fbb5 \
    --hash=sha256:c59e4265608da6a041f54646ecc0c9ecdbb19aaf14c4c684bb6c2114998cc415 \
    --hash=sha256:c6c0c13128a32eb04a51357e56a094e13aa8e6d3d1884de2e9ae923f6915e1a8 \
    --hash=sha256:cad7617727a96d189bd6f979d0fadf765198c7934e85f4edaba9bf3ad919a300 \
    --hash=sha256:d85dfab42dd672f87a7f76e9de7172962aee69fa12044f0d6e1a23cbd53fb80e \
    --hash=sha256:d9a0d12846d6ce434fb3857918eef4315ec9b4769deb020c75828798614bfcfd \
    --hash=sha256:d9b3e7d71bf6acff341233417abbdface29c647e3113892d9aaedc02eb4aa2bc \
    --hash=sha256:da707f14ea3c35ee463d50acd596d6488e4b2b4ae7cf77a5bf93f55c023d63e8 \
    --hash=sha256:e99e09ab7741f1281e2677f4c0058c7f5267d182530b09c87e4f6aa26adf3887 \
    --hash=sha256:ea2c01cdb16dc12156e455007c406dfaaece0c89aa4ba0e3b47586779f951d41 \
    --hash=sha256:f6449672f9c93316deb5e2839e18931f468670e44d5bd9b1301a5a9655d45c07 \
    --hash=sha256:f683dc6300317700025e41d89a43e0276692ded16113a3c43eab704d605c58e5 \
    --hash=sha256:f6b9d2aad499c769ee8287609ab0e6de99d8bcea99c6e6c2e64945259fd52fb2 \
    --hash=sha256:fbfb70ba01355251faf6b293171df49f73a88a1b6494db109ffea85442574458 \
    --hash=sha256:ff88a92cafde90888511242d1c54afcc1a8adbb6dc0a88fa7f87e29e92400d4a
packageurl-python==0.17.6 \
    --hash=sha256:31a85c2717bc41dd818f3c62908685ff9eebcb68588213745b14a6ee9e7df7c9
packaging==26.3 \
    --hash=sha256:d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c
pip-requirements-parser==32.0.1 \
    --hash=sha256:4659bc2a667783e7a15d190f6fccf8b2486685b6dba4c19c3876314769c57526
py-serializable==2.1.0 \
    --hash=sha256:b56d5d686b5a03ba4f4db5e769dc32336e142fc3bd4d68a8c25579ebb0a67304
pyparsing==3.3.3 \
    --hash=sha256:ece8c00a69cf01b45d0b1dedabb469c90d8caf996d4fda40f147627a122849a4
python-dateutil==3.0.0 \
    --hash=sha256:3c79630202e4152c6add678446984236efe4f57e84d8e892aab0637bab82e9fd
referencing==0.36.2 ; python_full_version < '3.10' \
    --hash=sha256:e8699adbbf8b5c7de96d8ffa0eb5c158b3beafce084968e2ea8bb08c6794dcd0
referencing==0.37.0 ; python_full_version >= '3.10' \
    --hash=sha256:381329a9f99628c9069361716891d34ad94af76e461dcb0335825aecc7692231
rfc3339-validator==0.1.4 \
    --hash=sha256:24f6ec1eda14ef823da9e36ec7113124b39c04d50a4d3d3a3c2859577e7791fa
rfc3986-validator==0.1.1 \
    --hash=sha256:2f235c432ef459970b4306369336b9d5dbdda31b510ca1e327636e01f528bfa9
rfc3987-syntax==1.1.0 \
    --hash=sha256:6c3d97604e4c5ce9f714898e05401a0445a641cfa276432b0a648c80856f6a3f
rpds-py==0.27.1 ; python_full_version < '3.10' \
    --hash=sha256:0dc5dceeaefcc96dc192e3a80bbe1d6c410c469e97bdd47494a7d930987f18b2 \
    --hash=sha256:12ed005216a51b1d6e2b02a7bd31885fe317e45897de81d86dcce7d74618ffff \
    --hash=sha256:16323f674c089b0360674a4abd28d5042947d54ba620f72514d69be4ff64845e \
    --hash=sha256:1b207d881a9aef7ba753d69c123a35d96ca7cb808056998f6b9e8747321f03b8 \
    --hash=sha256:2efe4eb1d01b7f5f1939f4ef30ecea6c6b3521eec451fb93191bf84b2a522418 \
    --hash=sha256:2fd50659a069c15eef8aa3d64bbef0d69fd27bb4a50c9ab4f17f83a16cbf8905 \
    --hash=sha256:3ce0cac322b0d69b63c9cdb895ee1b65805ec9ffad37639f291dd79467bee675 \
    --hash=sha256:42a89282d711711d0a62d6f57d81aa43a1368686c45bc1c46b7f079d55692734 \
    --hash=sha256:466bfe65bd932da36ff279ddd92de56b042f2266d752719beb97b08526268ec5 \
    --hash=sha256:4708c5c0ceb2d034f9991623631d3d23cb16e65c83736ea020cdbe28d57c0a0e \
    --hash=sha256:4e44099bd522cba71a2c6b97f68e19f40e7d85399de899d66cdb67b32d7cb786 \
    --hash=sha256:50c946f048209e6362e22576baea09193809f87687a95a8db24e5fbdb307b93a \
    --hash=sha256:55266dafa22e672f5a4f65019015f90336ed31c6383bd53f5e7826d21a0e0b83 \
    --hash=sha256:689fb5200a749db0415b092972e8eba85847c23885c8543a8b0f5c009b1a5948 \
    --hash=sha256:6f4461bf931108c9fa226ffb0e257c1b18dc2d44cd72b125bec50ee0ab1248a9 \
    --hash=sha256:80c60cfb5310677bd67cb1e85a1e8eb52e12529545441b43e6f14d90b878775a \
    --hash=sha256:8a3f29aba6e2d7d90528d3c792555a93497fe6538aa65eb675b44505be747808 \
    --hash=sha256:9024de74731df54546fab0bfbcdb49fae19159ecaecfc8f37c18d2c7e2c0bd61 \
    --hash=sha256:9d992ac10eb86d9b6f369647b6a3f412fc0075cfd5d799530e84d335e440a002 \
    --hash=sha256:a512c8263249a9d68cac08b05dd59d2b3f2061d99b322813cbcc14c3c7421998 \
    --hash=sha256:a75f305c9b013289121ec0f1181931975df78738cdf650093e6b86d74aa7d8dd \
    --hash=sha256:a9e960fc78fecd1100539f14132425e1d5fe44ecb9239f8f27f079962021523e \
    --hash=sha256:bbf94c58e8e0cd6b6f38d8de67acae41b3a515c26169366ab58bdca4a6883bb8 \
    --hash=sha256:cb56c6210ef77caa58e16e8c17d35c63fe3f5b60fd9ba9d424470c3400bcf9ed \
    --hash=sha256:dce51c828941973a5684d458214d3a36fcd28da3e1875d659388f4f9f12cc33e \
    --hash=sha256:dd2135527aa40f061350c3f8f89da2644de26cd73e4de458e79606384f4f68e7 \
    --hash=sha256:eb11a4f1b2b63337cfd3b4d110af778a59aae51c81d195768e353d8b52f88081 \
    --hash=sha256:f39f58a27cc6e59f432b568ed8429c7e1641324fbe38131de852cd77b2d534b0 \
    --hash=sha256:f41f814b8eaa48768d1bb551591f6ba45f87ac76899453e8ccd41dba1289b04b \
    --hash=sha256:fb89bec23fddc489e5d78b550a7b773557c9ab58b7946154a10a6f7a214a48b2 \
    --hash=sha256:fe0dd05afb46597b9a2e11c351e5e4283c741237e7f617ffb3252780cca9336a \
    --hash=sha256:ffce0481cc6e95e5b3f0a47ee17ffbd234399e6d532f394c8dce320c3b089c21
rpds-py==0.30.0 ; python_full_version == '3.10.*' \
    --hash=sha256:0c0e95f6819a19965ff420f65578bacb0b00f251fefe2c8b23347c37174271f3 \
    --hash=sha256:0d08f00679177226c4cb8c5265012eea897c8ca3b93f429e546600c971bcbae7 \
    --hash=sha256:0ed177ed9bded28f8deb6ab40c183cd1192aa0de40c12f38be4d59cd33cb5c65 \
    --hash=sha256:2771c6c15973347f50fece41fc447c054b7ac2ae0502388ce3b6738cd366e3d4 \
    --hash=sha256:33f559f3104504506a44bb666b93a33f5d33133765b0c216a5bf2f1e1503af89 \
    --hash=sha256:3896fa1be39912cf0757753826bc8bdc8ca331a28a7c4ae46b7a21280b06bb85 \
    --hash=sha256:389a2d49eded1896c3d48b0136ead37c48e221b391c052fba3f4055c367f60a6 \
    --hash=sha256:422c3cb9856d80b09d30d2eb255d0754b23e090034e1deb4083f8004bd0761e4 \
    --hash=sha256:46e83c697b1f1c72b50e5ee5adb4353eef7406fb3f2043d64c33f20ad1c2fc53 \
    --hash=sha256:47e77dc9822d3ad616c3d5759ea5631a75e5809d5a28707744ef79d7a1bcfcad \
    --hash=sha256:47f236970bccb2233267d89173d3ad2703cd36a0e2a6e92d0560d333871a3d23 \
    --hash=sha256:4c5f36a861bc4b7da6516dbdf302c55313afa09b81931e8280361a4f6c9a2d27 \
    --hash=sha256:51a1234d8febafdfd33a42d97da7a43f5dcb120c1060e352a3fbc0c6d36e2083 \
    --hash=sha256:5d4c2aa7c50ad4728a094ebd5eb46c452e9cb7edbfdb18f9e1221f597a73e1e7 \
    --hash=sha256:626a7433c34566535b6e56a1b39a7b17ba961e97ce3b80ec62e6f1312c025551 \
    --hash=sha256:73c67f2db7bc334e518d097c6d1e6fed021bbc9b7d678d6cc433478365d1d5f5 \
    --hash=sha256:74a3243a411126362712ee1524dfc90c650a503502f135d54d1b352bd01f2404 \
    --hash=sha256:7c64d38fb49b6cdeda16ab49e35fe0da2e1e9b34bc38bd78386530f218b37139 \
    --hash=sha256:7cee9c752c0364588353e627da8a7e808a66873672bcb5f52890c33fd965b394 \
    --hash=sha256:858738e9c32147f78b3ac24dc0edb6610000e56dc0f700fd5f651d0a0f0eb9ff \
    --hash=sha256:9027da1ce107104c50c81383cae773ef5c24d296dd11c99e2629dbd7967a20c6 \
    --hash=sha256:945dccface01af02675628334f7cf49c2af4c1c904748efc5cf7bbdf0b579f95 \
    --hash=sha256:c77afbd5f5250bf27bf516c7c4a016813eb2d3e116139aed0096940c5982da94 \
    --hash=sha256:ca28829ae5f5d569bb62a79512c842a03a12576375d5ece7d2cadf8abe96ec28 \
    --hash=sha256:cdc62c8286ba9bf7f47befdcea13ea0e26bf294bda99758fd90535cbaf408000 \
    --hash=sha256:d9a0ca5da0386dee0655b4ccdf46119df60e0f10da268d04fe7cc87886872ba7 \
    --hash=sha256:dbd936cde57abfee19ab3213cf9c26be06d60750e60a8e4dd85d1ab12c8b1f40 \
    --hash=sha256:f251c812357a3fed308d684a5079ddfb9d933860fc6de89f2b7ab00da481e65f
rpds-py==2026.9.1 ; python_full_version >= '3.11' \
    --hash=sha256:074a4d198bc34d9a8ea425114fc3ded6d11ec01f6a314a8db67454a5152d8834 \
    --hash=sha256:07deecbfce94c78473018bc7d10b337cc651d12df87a1eb2cb3e4024bc9c33d0 \
    --hash=sha256:08dae4a4095150a7c4545a1fb40b98e1ab1744fbc2770d92c977b9dadaa49ab6 \
    --hash=sha256:0da298fb372dc192610a4b9ecbc68a0cd8b675bbbd1fc519d01b41cfd658333e \
    --hash=sha256:0f045bb053c9057720d72c56dffe30dffdc05997b2897a827b9325f0ab6623fa \
    --hash=sha256:136a1c3fe4402b7008bc81cb62ee538481795b61a7e83df88dff3b3f02b726ff \
    --hash=sha256:159a7aab5c5e8b112c8830f54717ce56da1252ebdbb526f5be2df2309280b9e7 \
    --hash=sha256:1c2d1f6da5128eabf34e963d7163a818846075a52568250d006c4c953b40f903 \
    --hash=sha256:1d55198263bb51f557550c6ed2e6d1cb6a6fed6eb5c9120b741c5926bef8a45d \
    --hash=sha256:2693b2728bbcc48d09a981a356954b0c47c53ff25b545856f28a889ea619f69a \
    --hash=sha256:2c16ab111bc27c646ba8aa005d0527754edc538ebb636f0b1bf8e244b48d1945 \
    --hash=sha256:3b5a6f40f0a1486b4b36c888123afc67acdbd9f33235927acf5ff295429a0ba3 \
    --hash=sha256:457866b85daf5034296666168b84a69e0b2e89dc4f1af102b46f6448a60b9063 \
    --hash=sha256:46d80bc76b51a6c24f9944368c28d38b8bcbcea1da4f2f8d3ebc31a67e8c6ec6 \
    --hash=sha256:57492a550a1d88d29d003247e5f78dd8cf04a701fac0e4c8db8745a6d2504e0a \
    --hash=sha256:5943980471829f6de242a20b109de3111ba6b77e3af0ffc587028ac854b05e6c \
    --hash=sha256:617f59cde379b4f648a09797b7f683d04b90a46344cddab85639da5aff0f5531 \
    --hash=sha256:78326f4cb4427a56ba4996c0762b63be45f06b85f086526420d2b3a66e40f84d \
    --hash=sha256:7868b85224291c6cb6759f9b5adb9745f486d226f62b16a614dd5a2a5ab2b35b \
    --hash=sha256:a5cf77eb04f20b720be95265a3e00eb2a14814074255cc27069c551b2db53118 \
    --hash=sha256:addeda51556dac7c1a2f14cda62db8b621cd12afba3091d03a96c72932387eab \
    --hash=sha256:be3e47e2d91aa3942ff9bf4077a505226005abfc39b6f7554a91c1b9393986b9 \
    --hash=sha256:cdeaa99ce822dca76cfb1b993e9120c5ea212f2eb66d48950ad63c349668a018 \
    --hash=sha256:d7fca4eb6df565e2a928f1c7dad92d27db8f9df0f449e76423ed5d7e713ed445 \
    --hash=sha256:e01b3c878c8641913e688edd1b3f08658c6783d29cf6b826bd3c0d1ae7a1ffaa \
    --hash=sha256:e6d198bad4e49dd6732fbd636e2fc5c082f45c8cad0b4acb756b00c82c76072e \
    --hash=sha256:eac2f5dbafd585dfe31f86a23ebf0d3ba480a9d49ebc87947267b5608d4ea0cd \
    --hash=sha256:ec450527cbf485e13c8d3602a54f428ab0432fdade0ede75efd74b735421c871
six==1.17.0 \
    --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274
sortedcontainers==2.4.0 \
    --hash=sha256:a163dcaede0f1c021485e957a39245190e74249897e2ae4b2aa38595db237ee0
tomli==2.5.0 ; python_full_version < '3.11' \
    --hash=sha256:1245a6638fc4bb0a60af38a7d45413db34a13842027c77597c712c998c62fdf0 \
    --hash=sha256:19b0dd8749f4ea2f112c5fcfb3c5248390c899d7e2e173f1d91abee1fa0ff391 \
    --hash=sha256:20aa36de8f2cf87237143bc1fa1aae8d6612c09118f4da21c6a684db5dd1f6f9 \
    --hash=sha256:21e4cae4114aba25aa0d4f85cdf486d290fb35c0954d7bba536248da64d43066 \
    --hash=sha256:22185fad8a1e622f064e78008018a0dd3323550dcb479cb7a1d296888d74024f \
    --hash=sha256:32a7b79ac57a2e83670ce329ccf675798bc5a2094783a63676866b70503f2e2b \
    --hash=sha256:49096930c8d886c9bbdab62d2d0d17ce823ddeea522309a190b36245d5b49e01 \
    --hash=sha256:57b1c3b01fab802e2899bc3d168dca320e14165e2fd9fd584760fb4ca5826859 \
    --hash=sha256:5d8bac3d603c97e6854424e5b2b5b741bdbde387e09f162fb0446812b4a8362b \
    --hash=sha256:61ea1ebe1e55a34ea8199cc8dbff398d35027b82271c8ac4802fd3a1fd5b1bcc \
    --hash=sha256:6cf74416bdc94ae458b14e37286c1073081850ac8459a00d0c5efef5d44294c6 \
    --hash=sha256:6e95c7614e705bfe2b04b27aa124adec59752d15813df37e2156747cab3a006b \
    --hash=sha256:752e8b1aa6a4367ef8bf6a1a1e005540f7ed055ba36d7193796812ca5404eb52 \
    --hash=sha256:7ac2027d37c3afbdf4bdd377f2676f6f1d2122a5be1f1137b49dced590b37e75 \
    --hash=sha256:7ad1ea345759240d6463efa0ed1c704402752e49aa21476620738d74d72d8aa1 \
    --hash=sha256:86665cee9c4835b7a7f1e8ec2c719b5258d4dc782887aded5a8ae7352a96843b \
    --hash=sha256:8ff3a2ca028c7eee0c777f9a092038d0a594a9fa04e215f929a22c329e2cb142 \
    --hash=sha256:96243987194634bd411066ce40c952e108f86af04db533ecd8ac3ff2a85b1885 \
    --hash=sha256:984012f71908165449a951de2050d52f276bfe3aa5d5f570f63ddad814370374 \
    --hash=sha256:9b03d7dc168353b4132965bde20feceabaa470e570c6f59660dfae59b1f9eeb3 \
    --hash=sha256:b69564772b5c8f22ea5f498dff08cfa825045b4d4c4400529000bdf818aa3b2a \
    --hash=sha256:b8ade5023067f99fe72b88accd30d0ea05a158e9e32a11f124e731ea9695313f \
    --hash=sha256:bbaefc84548d754be821bba7c4141c4787dda182f9e77f2f87b71213529efa7b \
    --hash=sha256:bf0b5e8e0f68ebb494356e577c06c139161efd8d3b9050f93b39b7c26cc54ff0 \
    --hash=sha256:c414be4ed9d3cac80c42e348fa5a956117d1a48227f48026e31f59cb4a7671eb \
    --hash=sha256:c47300f9bf791808f77d82747691c4bb09cb14bdf3060cca99b42cdc4361d5a7 \
    --hash=sha256:d7e369fd63331746182360977b1892bfc215476a30d61612d732425311639f56 \
    --hash=sha256:ed53f7e89bb04f6d9e8e7799112360b0c4d5cbff067de0814c98c37c39b920f7 \
    --hash=sha256:f79203b3965b4000e91808aaa7c040206093f2b8bf86f455982f2274c9ccf442
typing-extensions==4.16.0 ; python_full_version < '3.13' \
    --hash=sha256:481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8
tzdata==2026.6 \
    --hash=sha256:0a10eec6e13ef16b627fabed9a5f2ba61a62b1c67f327305f4e7e412a70b4aec
uri-template==1.3.0 \
    --hash=sha256:a44a133ea12d44a0c0f06d7d42a52d71282e77e2f937d8abd5655b8d56fc1363
webcolors==24.11.1 ; python_full_version < '3.10' \
    --hash=sha256:515291393b4cdf0eb19c155749a096f779f7d909f7cceea072791cb9095b92e9
webcolors==25.10.0 ; python_full_version >= '3.10' \
    --hash=sha256:032c727334856fc0b968f63daa252a1ac93d33db2f5267756623c210e57a4f1d
VALYSTRUM_PY_LOCK

cd "$SCAN_PATH" || setup_failed "VALYSTRUM_PATH '$SCAN_PATH' is not a directory."

# 'auto' runs every generator whose manifest is present; otherwise only the ecosystems named.
want() {
  [ "$ECOSYSTEM" = "auto" ] && return 0
  case " $ECOSYSTEM " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

if want npm && [ -f package-lock.json ]; then
  echo "CycloneDX: npm (@cyclonedx/cyclonedx-npm $CDX_NPM_VERSION)"
  # From its lock file: every package at its locked version and SHA-512, nothing resolved, fetched through the
  # project's own npm registry (a mirror included).
  REGISTRY="$(npm config get registry)"
  (cd "$TOOLS/npm" && npm ci --silent --ignore-scripts --no-audit --no-fund --registry "$REGISTRY")
  # cyclonedx-npm walks the INSTALLED tree, not just the lockfile: the pipeline must run `npm ci` first.
  # --ignore-npm-errors: `npm ls` exits non-zero on extraneous/invalid packages (optional native deps, peer
  # mismatches). Those are still real installed components, so report them instead of failing.
  "$TOOLS/npm/node_modules/.bin/cyclonedx-npm" --ignore-npm-errors --output-format JSON --output-file "$BOM_DIR/npm.cdx.json"
fi

if want python; then
  PY_SUBCOMMAND=""
  PY_TARGET="."
  if   [ -f poetry.lock ];      then PY_SUBCOMMAND="poetry"
  elif [ -f Pipfile.lock ];     then PY_SUBCOMMAND="pipenv"
  elif [ -f requirements.txt ]; then PY_SUBCOMMAND="requirements"; PY_TARGET="requirements.txt"
  fi
  if [ -n "$PY_SUBCOMMAND" ]; then
    echo "CycloneDX: python ($PY_SUBCOMMAND, cyclonedx-bom $CDX_PY_VERSION)"
    python3 -m venv "$TOOLS/py"
    # From its lock file: every package's wheel checked against its locked SHA-256, nothing resolved.
    "$TOOLS/py/bin/pip" install --quiet --disable-pip-version-check --require-hashes --no-deps --only-binary=:all: -r "$TOOLS/cyclonedx-bom.txt"
    "$TOOLS/py/bin/cyclonedx-py" "$PY_SUBCOMMAND" --output-format JSON --output-file "$BOM_DIR/python.cdx.json" "$PY_TARGET"
  fi
fi

if want go && [ -f go.mod ]; then
  echo "CycloneDX: go (cyclonedx-gomod $CDX_GOMOD_VERSION)"
  go run "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v$CDX_GOMOD_VERSION" \
    mod -json -output "$BOM_DIR/go.cdx.json" .
fi

if want maven && [ -f pom.xml ]; then
  echo "CycloneDX: maven (cyclonedx-maven-plugin $CDX_MAVEN_VERSION)"
  mvn -B -q --strict-checksums "org.cyclonedx:cyclonedx-maven-plugin:$CDX_MAVEN_VERSION:makeAggregateBom" \
    -DoutputFormat=json -DoutputName=bom
  cp target/bom.json "$BOM_DIR/maven.cdx.json"
fi

shopt -s nullglob
BOMS=("$BOM_DIR"/*.cdx.json)
if [ "${#BOMS[@]}" -eq 0 ]; then
  setup_failed "No supported manifest found under '$SCAN_PATH'. Supported: package-lock.json (npm), requirements.txt / poetry.lock / Pipfile.lock (python), go.mod (go), pom.xml (maven)."
fi

SBOM="$OUT_DIR/sbom.cdx.json"
if [ "${#BOMS[@]}" -eq 1 ]; then
  cp "${BOMS[0]}" "$SBOM"
else
  # A components-only merge (deduplicated by purl): the ingest reads name, version, purl and licences, nothing else.
  jq -s '{
    bomFormat: "CycloneDX",
    specVersion: (.[0].specVersion // "1.5"),
    version: 1,
    components: (map(.components // []) | add
                 | unique_by(.purl // (.name + "@" + .version)))
  }' "${BOMS[@]}" > "$SBOM"
fi

COUNT=$(jq '(.components // []) | length' "$SBOM")
echo "CycloneDX $(jq -r '.specVersion // "?"' "$SBOM"): $COUNT components from ${#BOMS[@]} generator(s)."
if [ "$COUNT" -eq 0 ]; then
  setup_failed "The generated SBOM has 0 components: nothing to ingest. Install the dependencies (for example 'npm ci') before this step."
fi

# ── Upload ─────────────────────────────────────────────────────────────────────────────────────────────────────────
PAYLOAD="$TMP_DIR/valystrum-sbom-payload.json"
RESPONSE="$TMP_DIR/valystrum-sbom-response.json"
jq -c --arg source "$SOURCE" --arg asset "$ASSET" --arg complete "$COMPLETE" \
  '{source: $source, sbom: .} + (if $asset == "" then {} else {assetRef: $asset} end) + (if $complete == "true" then {complete: true} else {} end)' \
  "$SBOM" > "$PAYLOAD"

# Stamped HMAC-SHA256: the digest covers "<unix seconds>.<body>",
# over the exact bytes curl sends (--data-binary is verbatim). The platform
# accepts a stamp within five minutes and once, so every attempt signs
# afresh: a resent signature is refused as already used. The pause between
# attempts is at least a second, so each attempt carries a new stamp.
# Retries are safe: ingest upserts on (org, name, version, source), and a
# complete bill sent twice removes nothing the first did not.
for ATTEMPT in 1 2 3 4; do
  : > "$RESPONSE"  # curl leaves -o untouched when nothing answers: no earlier attempt's body in the error
  T=$(date +%s)
  SIGNATURE=$( { printf '%s.' "$T"; cat "$PAYLOAD"; } | openssl dgst -sha256 -hmac "$INGEST_SECRET" | awk '{print $NF}')
  CODE=$(curl -sS \
    -o "$RESPONSE" -w '%{http_code}' \
    -X POST "$INGEST_URL" \
    -H 'content-type: application/json' \
    -H "x-cs-signature: t=$T,v1=$SIGNATURE" \
    --data-binary @"$PAYLOAD") || CODE="000"
  # Retried as curl's own retry did: no answer, 408, 429 and 5xx.
  case "$CODE" in 000|408|429|5??) ;; *) break ;; esac
  if [ "$ATTEMPT" -lt 4 ]; then sleep $((1 << (ATTEMPT - 1))); fi
done

if [ "$CODE" != "201" ] && [ "$CODE" != "200" ]; then
  setup_failed "Valystrum ingest failed (HTTP $CODE): $(head -c 500 "$RESPONSE" 2>/dev/null)"
fi

INGESTED=$(jq -r '.data.ingested // 0' "$RESPONSE")
REMOVED=$(jq -r '.data.removed // 0' "$RESPONSE")
printf 'VALYSTRUM_COMPONENTS=%s\nVALYSTRUM_REMOVED=%s\n' "$INGESTED" "$REMOVED" > "$OUT_DIR/valystrum-sbom.env"
# shellcheck disable=SC2016  # Markdown backticks, not a command
printf '### Valystrum SBOM\n\nIngested **%s** components as source `%s`; removed **%s** the SBOM no longer lists.\n' "$INGESTED" "$SOURCE" "$REMOVED" > "$SUMMARY"
if [ "$ANNOTATIONS" = "azure" ]; then
  echo "##vso[task.setvariable variable=VALYSTRUM_COMPONENTS]$INGESTED"
  echo "##vso[task.setvariable variable=VALYSTRUM_REMOVED]$REMOVED"
  echo "##vso[task.uploadsummary]$SUMMARY"
fi
echo "Ingested $INGESTED components into Valystrum as source '$SOURCE'; removed $REMOVED it no longer lists."
