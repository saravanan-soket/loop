# `/patch` and `/audit`

Two sandboxed security workflows. Repository code only ever runs inside
rootless podman with `--network none`; the network is on only while an image
is built. You need [podman](https://podman.io) (rootless) on the machine.

## `/patch <target>`

Finds a vulnerability, proves it with a failing test, fixes it, and has a
trusted grader verify the fix in a fresh container.

```
/patch CVE-2022-36009                                 # a known CVE (Go modules)
/patch https://github.com/owner/repo                  # default branch, pinned to its commit
/patch https://github.com/owner/repo/tree/v1.2.3      # a branch, tag or commit
/patch ./services/api                                 # a local folder (copied; never modified)
/patch stop                                           # end a run early
```

Every stage prints a report and writes it to the run directory:

| # | Stage | What it does |
|---|---|---|
| 0 | resolve | CVE: cve.org + OSV records and fix commits. Repo: clone at a pinned commit, or copy the folder |
| 1 | scope | CVE: clone, vulnerable = the fix's parent. Repo: language, dependency install, build and test commands |
| 2 | split / sandbox | CVE: upstream fix → reference patch + hidden oracle tests. Repo: build the sandbox image |
| 3 | sandbox / baseline | CVE: build the image. Repo: static analyzers once → leads |
| 4 | confirm | CVE only: the upstream fix must fail-then-pass the hidden tests |
| 5 | agent | Loop assesses, reproduces with its own test, patches, verifies, submits a root-cause report |
| 6 | grade | Fresh container: A validate, B reproduce, C build, D regression (twice), E existing tests, G verdict |
| 7 | final | `report.md`, `report.json`, `attempt-N/candidate.patch` |

Lifecycle: `DISCOVERED → CLASSIFIED → BUILDABLE → REPRODUCIBLE → PATCH_VERIFIED`,
or a stop at `UNSUPPORTED`, `INCONCLUSIVE` or `FAILED` with the reason.

For a repository there is no known vulnerability and no hidden oracle: the
grader uses the agent's own reproduction test, so review the finding and the
test before trusting a `PATCH_VERIFIED`. For a CVE the hidden tests come from
the upstream fix and the grade has a score out of 12.

Apply the patch to your own copy with `git apply runs/.../attempt-N/candidate.patch`.

## `/audit <github-url>`

Reviews a repository and reports findings, without patching. Each finding is
labelled by how far it was corroborated: `poc-demonstrated` >
`tool-corroborated` (a static analyzer flags the same spot) > `cited` (the
location exists). Findings whose location cannot be verified are dropped.
Findings are candidates for human review, never a verdict.

Analyzers: Go (gosec, go vet, govulncheck), Python (bandit), npm audit for
JavaScript and TypeScript.

## While a run is active

Only the sandboxed `defensive__*` tools are offered, and they run without
asking, in every permission mode: they act inside the run's container on a
copy of the code. A `toolPermissions` deny rule still applies. Loop's own read,
write, edit and shell tools come back when the run finishes, on `/patch stop`
or `/audit stop`, or when you quit.

## Without the TUI

```
loop defensive patch <CVE | github-url | folder>
loop defensive audit <github-url>
loop defensive report <run-dir>      # print a finished report.md
```

These take the usual `--provider`, `--model` and `--output-format` flags.

## Where runs go

`$DEFENSIVE_RUNS`, or `~/.loop/defensive/runs`:

- `repo/<slug>/<run-id>/` and `repo/<slug>/latest` for repositories and folders
- `<CVE-ID>/<run-id>/` for CVEs; their hidden oracle stays in `~/.cache/defensive/hidden` (mode 0700)
- `audit/<slug>/<run-id>/` for audits

`DEFENSIVE_MAX_GRADES` (default 3) limits `grade_patch` calls per run;
`DEF_TEST_TIMEOUT` (seconds, default 600) limits each grader test command.

The feature is the `defensive` cargo feature of `loop-cli` (on by default).
