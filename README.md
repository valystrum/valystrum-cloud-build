# Valystrum for Google Cloud Build

Two scripts and the Cloud Build configurations that run them:

- **`valystrum-scan.sh`** with [`examples/cloudbuild-security-scan.yaml`](examples/cloudbuild-security-scan.yaml)
  scans each pull request for **leaked secrets**, **code weaknesses (SAST)** and **IaC misconfiguration** (Terraform,
  CloudFormation, Kubernetes, Helm, Dockerfile), prints the findings in the build log, and fails the build on a
  critical or high finding.
- **`valystrum-sbom.sh`** with [`examples/cloudbuild-sbom.yaml`](examples/cloudbuild-sbom.yaml) makes a **CycloneDX**
  bill of materials with the official CycloneDX generators and uploads it to your Valystrum software inventory, where
  its components are matched against CVE feeds and your licence policy.

Both are part of the Gold plan and above. This repository is licensed under the Apache License 2.0
([LICENSE](LICENSE)); the Valystrum platform it calls is not. The GitHub equivalents are
`valystrum/valystrum-pipeline` and `valystrum/valystrum-sbom`; the request, the signature and the retries are the same,
and so are the rules that a scan which cannot run never blocks a merge and that a failed SBOM upload fails its build.
Releases are listed in [CHANGELOG.md](CHANGELOG.md).

> **Status, 2026-10-29.** Written for Valystrum v0.21.0, live on app.valystrum.io since 2026-10-29. Cloud Build cannot
> be run outside Google Cloud, so these configurations were checked against Cloud Build's published schema, and the
> scripts were run end to end in the same images, but not yet in a Cloud Build trigger.


## Quick start

Copy the two scripts of a release into `.valystrum/` in your repository, and the two configurations from `examples/`:

```bash
REL=https://raw.githubusercontent.com/valystrum/valystrum-cloud-build/v1.0.0
mkdir -p .valystrum
curl -fsSL -o .valystrum/valystrum-scan.sh "$REL/valystrum-scan.sh"
curl -fsSL -o .valystrum/valystrum-sbom.sh "$REL/valystrum-sbom.sh"
curl -fsSL -O "$REL/examples/cloudbuild-security-scan.yaml"
curl -fsSL -O "$REL/examples/cloudbuild-sbom.yaml"
```

Replace `acme` in their URLs with your organisation's slug, then follow
[Setup](#setup-from-the-key-to-the-first-green-build): issue the repository's CI key in Valystrum, store its secret in
Google Secret Manager, and create the two triggers.

## Setup, from the key to the first green build

**1. Issue the repository's CI key in Valystrum.** An organisation owner or admin opens **Settings, CI pipeline keys**
and issues a key for the repository as `owner/repo`, which is what Cloud Build names it in `REPO_FULL_NAME`. The secret
(`cs_wh_...`) is shown once; the same key signs the scan and the SBOM upload. Each repository takes one of the plan's
repository slots; rotating a key does not. Every key names one repository: there is no organisation-wide key, so a
repository without a key of its own is refused with HTTP 401 `Invalid signature: sign with this repository's CI key`,
on the scan and on the SBOM upload alike. Over the API, from a signed-in admin session:

```bash
curl -X POST https://app.valystrum.io/api/v1/<org>/pipeline/config \
  -H "content-type: application/json" -H "cookie: <your signed-in session cookie>" \
  -d '{"repo": "acme/web-api"}'
```

The answer holds the secret as `webhookSecret`. `GET /api/v1/<org>/pipeline/config` lists the active
keys (never their secrets), `PATCH /api/v1/<org>/pipeline/config/<keyId>` changes a key's repository or label and
keeps its secret, and `DELETE /api/v1/<org>/pipeline/config/<keyId>` revokes it, which returns its repository slot.
**Settings, CI pipeline keys** lists, issues and revokes keys too. Gold includes 100 repositories and Enterprise a
custom number. From Gold, 25 more are an add-on at €100 a month or €1,000 a year. A new repository over the allowance
is refused with HTTP 409 `QuotaExceeded`.

**2. Store the secret in Secret Manager** as `valystrum-ci-secret`, and let the trigger's service account read it.
Enable the Secret Manager API in the project first (`gcloud services enable secretmanager.googleapis.com`). The account
to bind is the one selected on the trigger: Cloud Build runs a trigger's builds as that account and ignores one named
in the configuration.

```bash
printf '%s' 'cs_wh_...' | gcloud secrets create valystrum-ci-secret --data-file=-
gcloud secrets add-iam-policy-binding valystrum-ci-secret \
  --member="serviceAccount:<the trigger's service account>" --role=roles/secretmanager.secretAccessor
```

Run the two triggers as a service account of their own. A broadly used account, such as the Compute Engine default
service account that virtual machines and Cloud Run services in a project often run as, would let all of those read
the secret too. A dedicated account needs no more than the Secret Manager Secret Accessor role on `valystrum-ci-secret`
(above) and the Logs Writer role, plus write access to a bucket if you keep the reports (see
[Settings](#settings)):

```bash
gcloud iam service-accounts create valystrum-ci --display-name="Valystrum CI builds"
gcloud projects add-iam-policy-binding <project> \
  --member="serviceAccount:valystrum-ci@<project>.iam.gserviceaccount.com" --role=roles/logging.logWriter
```

Select it on both triggers. Anyone who may act as that account (the Service Account User role on it) and start builds
can read the secret through a build of their own, so grant that role only to the people who manage these triggers.

If an organisation policy limits where resources may live (`constraints/gcp.resourceLocations`, common for EU data
residency), Secret Manager refuses a secret with its default automatic replication: add
`--replication-policy=user-managed --locations=<your region, for example europe-west4>` to `gcloud secrets create`.
The commands in this step put the secret on the command line, where your shell history keeps it. To keep it out, read
it first (and the same way for `gcloud secrets versions add` when you rotate the key):

```bash
read -rs VALYSTRUM_CI_SECRET && printf '%s' "$VALYSTRUM_CI_SECRET" \
  | gcloud secrets create valystrum-ci-secret --data-file=- && unset VALYSTRUM_CI_SECRET
```

Store the secret exactly as Valystrum shows it, with no line break at its end: `printf '%s'` adds none, where `echo`
would, and the build signs with the value exactly as Secret Manager holds it.

**One secret per repository.** Each repository has a key of its own, and the configurations read the secret by a
fixed name in the build's project. Two repositories whose triggers run in the same Google Cloud project therefore need
two secrets: store the second under another name (for example `valystrum-ci-secret-web-app`), grant the trigger's
service account access to it, and change `versionName` in both of that repository's configurations to the new name. A
build that reads another repository's secret is refused with HTTP 401 `Invalid signature`: the scan then passes with
an `ERROR:` line in its log (unless `VALYSTRUM_FAIL_ON_ERROR` is on), and the SBOM build fails. The secret can also
live in another project: name that project in `versionName` and grant the role there.

The configurations read the secret through `availableSecrets` and `secretEnv`, so it reaches the step as
`VALYSTRUM_SECRET` and is never written into the configuration or the log. They also set
`options.logging: CLOUD_LOGGING_ONLY`: a build that runs as a service account you choose has to keep its log in
Cloud Logging or in a bucket of your own. The build log, and with it the findings, is then in Cloud Logging, so that
account needs to write logs (the Logs Writer role). To keep build logs in a Cloud Storage bucket of your own instead,
use `GCS_ONLY` with a `logsBucket`.

**Rotating the key.** Issuing the key again for the same repository under **Settings, CI pipeline keys** rotates its
secret. Over the API, add `"regenerateSecret": true` to the step 1 call; without it, the call leaves the secret alone
and returns none. The old secret stops working at once, so add the new one as a new version straight away, then
disable the old version:

```bash
printf '%s' 'cs_wh_...' | gcloud secrets versions add valystrum-ci-secret --data-file=-
gcloud secrets versions disable <the old version's number> --secret=valystrum-ci-secret
```

The configurations read `versions/latest`, so the next build signs with the new secret. A build that read the old one
is refused with HTTP 401 `Invalid signature`: the scan passes with an `ERROR:` line unless `VALYSTRUM_FAIL_ON_ERROR` is
on, and the SBOM build fails. Rotating never takes a repository slot.

**3. Copy the files into your repository:** `valystrum-scan.sh` and `valystrum-sbom.sh` to `.valystrum/`, and the two
configurations from `examples/`. Replace `acme` in the URLs with your organisation's slug. **Settings, CI pipeline
keys** shows the scan's URL; the SBOM's is the same with `sbom/ingest` in place of `pipeline/scan`. If your default
branch is not `main`, change `VALYSTRUM_DEFAULT_BRANCH=main` in `cloudbuild-security-scan.yaml`, and the `^main$` of
the push triggers in steps 4 and 5, to its name. With a wrong name, your real default branch counts as one branch among
the others: a fix there closes a finding only when no other branch's latest scan still finds it.

**4. Create the scan's trigger.** With the repository connected to Cloud Build (GitHub, GitHub Enterprise, GitLab or
Bitbucket through a Cloud Build repository connection), create a trigger on **Pull request** events for your target
branches, with the configuration `cloudbuild-security-scan.yaml`. Add a second trigger on **Push to a branch**
(`^main$`) with the same configuration, so each merge is scanned and the default branch decides what a fix closes (see
[The branch](#the-branch)).

A pull request's build runs the configuration and `.valystrum/valystrum-scan.sh` as the pull request has them, as the
trigger's service account, so it can read `valystrum-ci-secret`. Someone outside your organisation could change them to
print the secret, and the secret signs scans and SBOM uploads that close this repository's findings in Valystrum. Set
the trigger's **Comment control**, where the connection offers it, to **Required except for owners and
collaborators**: a pull request from anyone else then builds only after an owner or collaborator comments `/gcbrun` on
it. Where it does not, require approval before the trigger's builds run. Read any change to `.valystrum/` and the
configurations before you let such a build run. A pull request's branch is sent under its own name (`_HEAD_BRANCH`),
so a pull request from a fork's `main` counts as a scan of your default branch and can close findings as one.

**5. Create the SBOM's trigger** on **Push to a branch** (`^main$`) with `cloudbuild-sbom.yaml`. The example installs an
npm project's dependencies first, in the same pinned image: the generator reads the installed `node_modules`, not the
lockfile alone, and an SBOM with no components fails the build. For Python, Go or Maven, use an image with that
toolchain (python3 with venv, go, or mvn) and bash, curl and openssl.

**6. Make the scan a merge gate.** Cloud Build reports each build to the pull request as a check (GitHub) or a
pipeline status (GitLab, Bitbucket). Require it in the branch's protection rules. The build fails on a critical or
high finding; only a required check stops the merge.

**7. Open a pull request.** A green first build reads `Scan complete: 0 finding(s), passed=true.` Once the change
reaches `main` and the SBOM trigger runs, its build reads
`Ingested N components into Valystrum as source 'acme/web-api'; removed 0 it no longer lists.` The scan then shows in
Valystrum's **Dev Pipeline** module, its findings in **Findings**, and the components under **SBOM & Licences**.

When the build's clone is shallow, the scan fetches the history and the target branch from `origin` before it diffs
(`Shallow clone detected: fetching history so the diff has a base.`). If the target branch cannot be fetched, the scan
warns `Base '...' is not in this clone` and compares with the previous commit, so it reads only the last commit's
changes. If the clone holds only the commit built and the build cannot fetch from your repository, there is no previous
commit either: the scan compares the commit with itself, reports `No changes to scan.` and passes without checking
anything. Check the first builds of both triggers for `Diffing <base>...HEAD` followed by `N file(s) changed.` with N
above 0. A push build that diffs nothing gives the default branch no read of the code.

## The security scan

### What it checks

| Check | Reads | Finds |
|---|---|---|
| Leaked secrets | the lines the change adds | AWS access keys, GitHub tokens, Stripe live secret keys and private keys (critical); Google API keys and Slack tokens (high); JWTs and generic API keys (medium: reported, never blocking) |
| Code analysis (SAST) | each changed file, whole | weaknesses in JavaScript and TypeScript, Python, Java, Go, C#, Scala, Kotlin, Swift and Objective-C, with Opengrep and a licence-clean rule pack: an error-level rule is high, a warning medium, an info low, and command, SQL, code or eval injection, unsafe deserialisation, hard-coded credentials and SSRF are critical |
| IaC | each changed file, whole | Terraform, CloudFormation, Kubernetes, Helm and Dockerfiles, with Trivy's checks: critical, high and medium as Trivy grades them; low is not reported |

A Google Cloud service account key file is found by its private key (critical). Google OAuth client secrets and access
tokens are not among the secret families. Secrets are not reported in the common lock files (`package-lock.json`,
`yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Gemfile.lock`, `go.sum`, `Cargo.lock`), in `node_modules`, `vendor`,
`dist`, `build`, `out`, `coverage` or `.next` directories, in minified, snapshot or source-map files, or in `.example`,
`.sample`, `.template` or `.dist` files, and neither is a value that reads as a placeholder (one containing `example`,
`xxxx`, `placeholder`, `changeme`, `your_key` (or `your_token`, `your_secret`), `dummy` or `redacted`, or a `<...>`
stand-in). Ruby, PHP, C and any
language not listed get the secret check only. Code analysis and the IaC checks see only the files the change sends, so
a Terraform variable or a Helm value set in a file the change did not touch is unknown to them. The two engines run
side by side with 20 seconds each and Valystrum waits 25 seconds, so a large change set can come back as `timeout` (a
`WARNING:` line, see [What blocks a merge](#what-blocks-a-merge-and-what-does-not)).

### Settings

The configuration sets these in the step's `env`, or works them out from Cloud Build's substitutions
(`options.automapSubstitutions: true` hands every substitution to the step as a variable).

| Variable | Default | What it does |
|---|---|---|
| `VALYSTRUM_SCAN_URL` | required | `https://app.valystrum.io/api/v1/<org>/pipeline/scan` |
| `VALYSTRUM_SECRET` | required | The repository's CI secret, from Secret Manager |
| `VALYSTRUM_REPO` | `REPO_FULL_NAME` | The repository as its CI key names it. It picks the key, so it must match exactly |
| `VALYSTRUM_BRANCH` | `_HEAD_BRANCH`, or `BRANCH_NAME` on a push | The branch the change is on. Without it the scan gates the change but closes nothing in Valystrum |
| `VALYSTRUM_BASE` | `_BASE_BRANCH` | What the change is compared with: a pull request's target branch, fetched when the clone lacks it; the previous commit when nothing names it |
| `VALYSTRUM_COMMIT` | `COMMIT_SHA` | The commit scanned |
| `VALYSTRUM_PR_NUMBER` | `_PR_NUMBER` | The pull request's number |
| `VALYSTRUM_SEQUENCE` | not set | Cloud Build numbers no builds, so the scan sends no run number and Valystrum orders a branch's scans by the commit's time (see The branch). Set it only to a number that grows with each new build and that a retry keeps |
| `VALYSTRUM_DEFAULT_BRANCH` | `main` in the example; else what the clone's `origin` names | The repository's default branch: a scan of it decides a finding once it has read the file. Left unknown, the build warns |
| `VALYSTRUM_PATHS` | empty | Space-separated pathspecs that narrow the diff, and so the secret scan. The files sent for code analysis are every changed file all the same |
| `VALYSTRUM_SEND_FILES` | `true` | Send the changed files, which code analysis and the IaC checks need. Off, only secrets are scanned |
| `VALYSTRUM_FAIL_ON_FINDINGS` | `true` | Fail the build on a critical or high finding. Off, the build only reports |
| `VALYSTRUM_FAIL_ON_ERROR` | `false` | Also fail the build when the scan could not run (no jq, no answer, a refusal such as a wrong secret), the platform could not complete it, or its code and IaC scanner did not finish the files sent |
| `VALYSTRUM_OUT_DIR` | `valystrum-reports` | Where the outputs go: `summary.md` and `valystrum-scan.env` (`VALYSTRUM_PASSED`, `VALYSTRUM_FINDINGS`, `VALYSTRUM_SCAN_ID`), which later steps of the same build can read from the workspace |

The step's image, `buildpack-deps:trixie-scm` pinned by digest, has bash, git, curl and openssl. It has no jq, so the
script fetches jq 1.8.2 and checks it against its SHA-256 before it runs it (x86_64 and arm64).

The script also reads `VALYSTRUM_ANNOTATIONS`, `VALYSTRUM_CODEQUALITY` and `VALYSTRUM_JUNIT`, which the Azure Pipelines,
GitLab and AWS CodeBuild integrations use; Cloud Build has no view for them. The workspace is discarded when the build
ends. To keep `summary.md`, the SBOM build's `sbom.cdx.json`, or a JUnit report (`VALYSTRUM_JUNIT` set to a path under
`valystrum-reports/`), add an `artifacts` section to the configuration and let the service account write to that
bucket:

```yaml
artifacts:
  objects:
    location: gs://<your bucket>/valystrum/
    paths: ['valystrum-reports/*']
```

### The branch

The configuration sends the pull request's head branch, or the pushed branch, and each scan that reads a file in full
is that branch's read of it. Once the repository's default branch (`VALYSTRUM_DEFAULT_BRANCH`) has read a file, its
scans decide that file's findings: a fix closes a finding when it reaches the default branch, and a pull request or an
old branch that still carries the finding neither reopens nor holds it. Until the default branch has read the file,
every branch that read it holds the finding while its latest scan still finds it, so a fix on a pull request closes a
finding only when the default branch has not read that file and no other branch still finds it. Add the push trigger
on the default branch (step 4) so it reads the code. A leaked secret is the one exception: when no scan that decides
it still finds it, its finding stays open with the note
`No longer visible to the code scan of <day>: confirm you rotated it, then close it`, because whoever copied the
secret still has it. A file the change deletes closes its other findings as a fix does, and a renamed or moved file
takes its findings to its new path (if that move fails, the next scan finishes it).

Cloud Build numbers no builds, so Valystrum orders a branch's scans by the commit's time: a build of an older commit
that finishes after a newer one, or a retried old build, cannot reopen what the newer scan closed or close what it
saw. A force-push back to an older commit is the older scan too, so the branch's findings stand as the newer commit's
scan left them until the next push. A push is compared with the previous commit (Cloud Build does not name the commit
before a push), so a push of several commits is scanned as its last one. Whenever the scan compares with the previous
commit (every push build, and a pull request build whose target branch could not be fetched), it reads only that
commit's change: a secret added in an earlier commit of the same push is not seen, even while it is still in the code,
and code analysis and the IaC checks read only the files that commit touched. A pull request build reads the whole
change, so merge through pull requests to have every commit checked.

The commit's time is its committer time as git records it, not the time of the push: a rebase or an amend gives the
commit a new time, so its scan counts as newer, and a commit made on a machine whose clock ran behind counts as older
than it is. The time is kept to the second, so two commits made in the same second count as equally new, and whichever
of their builds finishes last decides. When the build cannot read the commit's time (the commit is not in the clone),
the time the scan reached Valystrum orders it instead. Cloud Build's `BUILD_ID` is an identifier, not a count, so it
cannot serve as `VALYSTRUM_SEQUENCE`. A value that is not all digits is dropped without a warning, and the scan then
sends no run number. Setting a run number later is safe: two scans are compared by run number only when both carry one,
and by the commit's time otherwise.

Findings are kept per repository name. A renamed repository's earlier code findings stay under its old name: once its
key is rebound to the new name (see [Troubleshooting](#troubleshooting)), the scans under the new name report what they
find as new findings (one you accepted or marked a false positive under the old name included) and never close the old
name's findings, so resolve those in **Findings**. Alternatively, keep the old name: leave the key as it is and set
`VALYSTRUM_REPO` (the scan) and `VALYSTRUM_SOURCE` (the SBOM) in the steps' `env` to the name it names.

### What blocks a merge, and what does not

The build fails when the scan reports any **critical or high** finding (with `VALYSTRUM_FAIL_ON_FINDINGS=true`). Code
analysis and the IaC checks read the whole of every changed file, so a critical or high finding already in a file the
change touches fails the build too, even on a line the change did not touch. The secret scan reads only the lines the
change adds.

A scanner outage never blocks you unless you ask it to: when the build has no jq and cannot fetch one, when the scan
endpoint cannot be reached or refuses the request, when the platform answers that it could not complete the scan, or
when its code and IaC scanner did not finish the files sent, the build passes, with an `ERROR:` or `WARNING:` line in
the log that says what did not run. `VALYSTRUM_FAIL_ON_ERROR=true` fails the build in all four cases. Turn it on once
the setup works, or a rotated secret or a plan change turns the gate off without failing a build.

An incomplete setup fails the build whatever `VALYSTRUM_FAIL_ON_ERROR` says: an empty `VALYSTRUM_SCAN_URL`,
`VALYSTRUM_SECRET` or `VALYSTRUM_REPO`, a build whose source is not a git checkout, or a clone that holds only the
commit built and cannot fetch its base (step 7).

Each build is judged on its own scan's findings. Accepting a finding or marking it a false positive in Valystrum keeps
that verdict there, but does not change the gate: a change that still carries a critical or high finding fails.

### Where the findings show

Cloud Build has no annotation format of its own, so the findings go to the build log: a summary table, then one line
per finding (`CRITICAL SECRET-aws_access_key deploy.env:1 ...`), with `ERROR:` and `WARNING:` lines for what failed
or did not run.

Unlike the GitHub Action, the script posts no comment on the pull request: the result reaches it as the build's status
(step 6), and the findings are in the build log and Valystrum. The log stays in your Google Cloud project: on GitHub
the check links to the build in the Google Cloud console, so a developer without access to the project sees the build
fail but not why. Give the people who fix findings the Cloud Build Viewer role, and Logs Viewer since the log is kept
in Cloud Logging, or let them read the scan in Valystrum's **Dev Pipeline** module.

In Valystrum the findings show in the **Dev Pipeline** module and **Findings**, one finding per repository,
rule and file. A detected secret is also listed under **Data Security**, **Secrets**, scoped to this repository and
file, so the same key leaked in two repositories stays two findings. It is only ever shown as a masked preview
(`AKIA••••3456`): in the log, in **Findings** and under **Data Security**, **Secrets**.

## The SBOM upload

The SBOM build has no fail-open rule: an empty `VALYSTRUM_INGEST_URL`, `VALYSTRUM_SECRET` or `VALYSTRUM_SOURCE`, a
missing manifest, an SBOM with no components, a jq that cannot be fetched, or an upload that is refused or still
unanswered after four attempts fails it. An upload that connects but gets no answer has no time limit of its own: it
waits until the build times out (see [Troubleshooting](#troubleshooting)).

### Settings

| Variable | Default | What it does |
|---|---|---|
| `VALYSTRUM_INGEST_URL` | required | `https://app.valystrum.io/api/v1/<org>/sbom/ingest` |
| `VALYSTRUM_SECRET` | required | The repository's CI secret, from Secret Manager |
| `VALYSTRUM_SOURCE` | `REPO_FULL_NAME` | The label the components are grouped under. It also picks the CI key, so it must equal the repository the key was issued for |
| `VALYSTRUM_PATH` | `.` | The directory holding the manifests. Its subdirectories are not searched |
| `VALYSTRUM_ECOSYSTEM` | `auto` | Every generator whose manifest is present, or a space-separated subset of `npm python go maven` |
| `VALYSTRUM_ASSET` | empty | The name or hostname of the Valystrum asset these components belong to. When empty, the components link to an asset whose name or hostname equals `VALYSTRUM_SOURCE` (case aside), if there is one |
| `VALYSTRUM_COMPLETE` | `false` (the example sets `true`) | `true` when this build's SBOM is the whole of the source: the source's components it no longer lists are removed in Valystrum and their CVE findings resolve, unless the CVE still affects the version the SBOM now lists for that package (the finding then moves to that version and stays open); a licence that no listed component carries any more resolves its finding. This holds only when every named component in the SBOM carries a version. Otherwise the upload only adds, says nothing, and `VALYSTRUM_REMOVED` reads `0`. Only from the default branch; `false` when several builds or steps upload parts of one source (see [Several directories](#several-directories)) |
| `VALYSTRUM_OUT_DIR` | `valystrum-reports` | Where `sbom.cdx.json`, `valystrum-sbom.env` (`VALYSTRUM_COMPONENTS`, `VALYSTRUM_REMOVED`) and `summary.md` go |

Two pushes in quick succession start two builds side by side. If the older one finishes last, its complete upload
puts the older set back until the next push's build: rare, and set right by the next build.

New components are checked against the vulnerabilities Valystrum already knows as soon as they arrive.

A source that is no longer uploaded (a renamed repository, an archived one) keeps its components and their open
findings. A renamed repository uploads under its new name once its key is rebound with the `PATCH` in
[Troubleshooting](#troubleshooting), because `VALYSTRUM_SOURCE` is `REPO_FULL_NAME`; the old name stays a source of its
own until you retire it. Its page under **SBOM & Licences** has a **Retire this source** panel: **Retire source**,
confirmed with **Yes, retire**, removes its components, resolves their CVE matches and resolves their open CVE and
licence findings with a note that the source was retired. Accepted risks and false positives stay. From a signed-in
session, `POST /api/v1/<org>/sbom/retire` with `{"source": "<the old name>"}` does the same. An upload under the same
name later starts the source again. The scan's findings stay under the old name too (see [The branch](#the-branch)).

A repository that still exists but rarely changes shows as stale under **SBOM & Licences** too, once its last upload is
more than 30 days old. To keep its SBOM fresh, add a manual trigger on the default branch with `cloudbuild-sbom.yaml`
and run it on a schedule (the trigger's **Run on schedule** creates a Cloud Scheduler job for it).

### The generators

| Manifest | Generator | How it and everything it installs are locked |
|---|---|---|
| `package-lock.json` | `@cyclonedx/cyclonedx-npm` 6.0.1 | its whole tree from a lock file carried in the script (`npm ci`), each package by its SHA-512, fetched through your npm registry; nothing is resolved |
| `poetry.lock`, `Pipfile.lock` or `requirements.txt` (the first found) | `cyclonedx-bom` 7.6.0 | its whole tree from a hashed requirements file carried in the script (`pip --require-hashes --no-deps`), each wheel by its SHA-256, in a virtual environment; nothing is resolved |
| `go.mod` | `cyclonedx-gomod` 1.12.0 | `go run` at that version builds from the module's own `go.sum`, every module checked against Go's checksum database (sum.golang.org) |
| `pom.xml` | `cyclonedx-maven-plugin` 2.9.3 | the plugin's version fixes every dependency's version, each checked against the repository's checksums (`--strict-checksums`) |

Each generator is pinned to its newest release of 2026-10-28. The Python lock covers CPython 3.9 and later on Linux
(x86_64 and aarch64); the npm generator runs without its optional schema validators, which Valystrum does not need
because it reads the components itself. Several ecosystems in one directory are merged into
one component list.

The npm generator asks for Node.js 20.18 or later (22.9 or later on the 22 line) and npm 9 or later. It is installed
from the registry your project's npm configuration names, but in a directory of its own, so credentials kept only in
the repository's `.npmrc` do not reach it: a registry that needs a token, such as an Artifact Registry npm repository,
needs that token in the build's user-level `~/.npmrc` (Cloud Build keeps the home directory from step to step). A
Python mirror has to serve PyPI's own wheels, or the hash check refuses them.

### Several directories

The SBOM step reads only the directory `VALYSTRUM_PATH` names. For manifests in further directories, add an install
step and an SBOM step per directory to `cloudbuild-sbom.yaml`:

```yaml
  - id: install-billing
    name: node:26.12.1-trixie@sha256:b5f0e27e7423ea242b37af44c8c856e28f7e37d4fac23cb430cb618874ff8517
    dir: services/billing
    entrypoint: npm
    args: ["ci", "--ignore-scripts", "--no-audit", "--no-fund"]

  - id: valystrum-sbom-billing
    name: node:26.12.1-trixie@sha256:b5f0e27e7423ea242b37af44c8c856e28f7e37d4fac23cb430cb618874ff8517
    env:
      - VALYSTRUM_INGEST_URL=https://app.valystrum.io/api/v1/acme/sbom/ingest
      - VALYSTRUM_PATH=services/billing
      - VALYSTRUM_COMPLETE=false
      - VALYSTRUM_OUT_DIR=valystrum-reports/billing
    secretEnv:
      - VALYSTRUM_SECRET
    script: |
      #!/usr/bin/env bash
      export VALYSTRUM_SOURCE="${VALYSTRUM_SOURCE:-${REPO_FULL_NAME:-}}"
      exec bash .valystrum/valystrum-sbom.sh
```

Each such step uploads under the repository's one source, so set `VALYSTRUM_COMPLETE=false` on all of them, the
example's own step included: a complete upload removes the components the other steps sent. To remove what is gone,
either generate once from a manifest that covers every module (a Maven aggregator `pom.xml` is built with
`makeAggregateBom`) with `VALYSTRUM_COMPLETE=true`, or give each module a source of its own. In that case, issue a key
for exactly that label (for example `acme/mono/billing`; each label takes a repository slot), store its secret in
Secret Manager under a name of its own that the trigger's service account may read, add it to `availableSecrets` with
an `env` of its own (`VALYSTRUM_SECRET_BILLING`), list that name in the step's `secretEnv`, and add
`export VALYSTRUM_SECRET="$VALYSTRUM_SECRET_BILLING" VALYSTRUM_SOURCE=acme/mono/billing` to the step's script before its
`exec` line. A module with a source of its own can then upload with `VALYSTRUM_COMPLETE=true`.

## What is sent, and what never is

The scan sends the repository name, the branch, the commit, the pull request's number, the commit's committer time
(`committedAt`, never later than now), the repository's default branch (`defaultBranch`) and, only when you set
`VALYSTRUM_SEQUENCE`, a run number (`sequence`), the diff (base64) and, with `VALYSTRUM_SEND_FILES`, the changed
files' contents: at most 300 files, each at most 512 KB, about 1.5 MB in all,
binary files never; the whole request must stay under 2 MB (over it, the files are dropped and only secrets are
scanned; a request still over 2 MB without them is refused with HTTP 413). The SBOM upload sends the CycloneDX
document the generators made (one generator's whole document, or the components of several merged into one list), from
which Valystrum keeps each component's name, version, ecosystem (from its purl) and first licence. It also sends the
source label, the asset name when `VALYSTRUM_ASSET` is set, and `complete` when it is `true`. Each request is signed
with HMAC-SHA256 over `"<unix seconds>.<body>"` under your CI secret, in the header
`X-CS-Signature: t=<seconds>,v1=<hex>`; Valystrum accepts a signature once and within five minutes, so every
retry is signed afresh. The script retries on no answer, 408, 429 and 5xx (three attempts for the scan, four for the
SBOM).

Never sent: the CI secret itself, other substitutions or variables, Google Cloud credentials, files the change did not
touch, the repository's history, or anything else in the workspace. Valystrum does not keep the diff or the files: it
scans them and keeps the scan record, the findings (a secret only as its masked preview, and under Data Security,
Secrets also with its location and a one-way fingerprint) and the SBOM's components.

## What the builds reach

The scan reaches `app.valystrum.io`, your repository's `origin` for the history and the target branch, and
`github.com` and `release-assets.githubusercontent.com` for jq (the scan's image has none; GitHub redirects the download
there).
The SBOM build reaches `app.valystrum.io`, `github.com` and `release-assets.githubusercontent.com` for jq when its image
has none, and the generators' own sources: your npm registry, the package index pip is set to, the Go module proxy and
sum.golang.org, or your Maven repositories. A private pool without internet access needs a route to each, or images
that already carry jq, and mirrors of the generators' sources.

Both configurations pull their images from Docker Hub (`buildpack-deps` for the scan, `node` for the SBOM), pinned by
digest. A private pool without internet access pulls them through a registry it reaches, such as an Artifact Registry
remote repository for Docker Hub, with the image's name changed and its digest kept.

## Troubleshooting

| Symptom | Cause |
|---|---|
| The build fails before the step with a Secret Manager error | The trigger's service account cannot read `valystrum-ci-secret` (step 2), the secret's name differs, or the Secret Manager API is not enabled in the project |
| `VALYSTRUM_REPO is empty` or `VALYSTRUM_SOURCE is empty` | The build has no `REPO_FULL_NAME` (it was not started by a trigger on a connected repository): set the variable in the step's `env` |
| `This is not a git checkout`, or `Base '...' is not in this clone` | The build's source holds no git history (a manual `gcloud builds submit` uploads files only: run the scan from a trigger on a connected repository), or the target branch could not be fetched from `origin`: the scan then compares with the previous commit and reads only the last commit's changes, so let the build fetch from your repository (step 7) |
| `No changes to scan.` | The diff is empty: nothing changed under `VALYSTRUM_PATHS`, or the change adds nothing to its base. The build passes whatever `VALYSTRUM_FAIL_ON_ERROR` says. An unreachable base ends here too when the clone holds only the commit built and cannot fetch from `origin`: nothing was checked, so let the build fetch from your repository (step 7) |
| `No branch named (VALYSTRUM_BRANCH)` | A build no branch or pull request trigger started: the scan gates the change but closes nothing in Valystrum |
| HTTP 401 `Invalid signature: sign with this repository's CI key` (the scan and the SBOM upload alike) | One answer for each of these, so it tells nobody which organisations exist or which repositories have a key. A wrong or rotated secret in `valystrum-ci-secret` (see Rotating the key in step 2), another repository's secret read under the same name in the same project (see One secret per repository in step 2), or a secret stored with a line break at its end: the step signs with the value exactly as Secret Manager holds it, so store it with `printf '%s'` as in step 2 (`echo` adds a line break) or, in the console, paste it without one. The organisation slug in `VALYSTRUM_SCAN_URL` or `VALYSTRUM_INGEST_URL` is wrong. Or there is no active key for this repository (there is no organisation-wide key to fall back on): step 1 was not run for it, its key was revoked, or the key names it differently from `REPO_FULL_NAME`, case included. The log does not print the name the build sent: add `echo "VALYSTRUM_REPO=$VALYSTRUM_REPO"` before the `exec` line of the scan's configuration to see it. A renamed repository: `PATCH /api/v1/<org>/pipeline/config/<keyId>` with `{"repo": "<new name>"}`, which keeps the secret (then retire the old SBOM source, see [The SBOM upload](#the-sbom-upload), and resolve the old name's code findings, see [The branch](#the-branch)). If the new name ever had a key of its own, revoked or not, the rebind fails: issue a key for the new name in step 1 instead, store its secret in `valystrum-ci-secret`, and revoke the old name's key |
| HTTP 401 `Signature timestamp outside the five-minute window` | The build's clock is off by more than five minutes |
| HTTP 401 `Signature already used` | The same signed request reached Valystrum twice. Every attempt, retries included, signs afresh, so this comes from a manual replay, or from two triggers that fired for the same event in the same second with the same configuration: keep one |
| HTTP 400 `No valid components found in SBOM payload` | No component in the SBOM has both a name and a version, so nothing could be stored. The script's own 0-component check also counts components without a version |
| HTTP 403 `FeatureLocked` | The organisation is below the Gold plan |
| HTTP 403 `Organization is suspended` (the SBOM build) | Valystrum has suspended the organisation: SBOM uploads are refused until it is reinstated. Contact your administrator |
| HTTP 413 | The scan's request is over 2 MB even without file contents (narrow it with `VALYSTRUM_PATHS`), or the SBOM is over 8 MB |
| HTTP 429 | More than 60 scans, or 30 SBOM uploads, a minute for the organisation, counted only once a request's signature checks out; or more than 300 scan requests, or 150 SBOM requests, a minute from one address, signed or not (builds behind one NAT share an address) |
| Every build warns `could not complete the scan (scan_error)` | The platform's scanner failed after it accepted the request |
| `jq is not installed, and jq 1.8.2 could not be fetched` | The build cannot reach github.com or release-assets.githubusercontent.com (a private pool without internet access): use an image with jq, see [What the builds reach](#what-the-builds-reach). The scan then passes unless `VALYSTRUM_FAIL_ON_ERROR` is on; the SBOM build fails |
| `No supported manifest found` or `0 components` | No manifest in `VALYSTRUM_PATH`, or the dependencies were not installed before the step |
| The build ends with status `TIMEOUT` | Cloud Build stops a build after ten minutes unless the configuration sets `timeout`. A large repository's history fetch, a first Maven or Go generator run, or an SBOM upload that gets no answer (the upload has no time limit of its own, so it waits for the build's) can take longer: add `timeout: 1200s` at the top level of the configuration |
| `$'\r': command not found` | The script was committed with Windows line endings: commit `.valystrum/*.sh` with LF (`*.sh text eol=lf` in `.gitattributes`) |

## Updating

Releases follow semantic versioning. To update, copy the scripts of a newer release into `.valystrum/`, and move the
images' digests when you choose to; the rules the scan applies live in Valystrum and change with the platform, not
with these scripts. The scripts are written from one canonical copy in the Valystrum repository, which also serves
the GitLab, Azure Pipelines and AWS CodeBuild integrations, so a fix reaches all of them at once.
