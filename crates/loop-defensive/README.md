# loop-defensive

Sandboxed security workflows for Loop: `/patch` (find, reproduce, fix and
grade a vulnerability) and `/audit` (report corroborated findings). See
[docs/defensive.md](../../docs/defensive.md).

The host drives rootless podman; no helper code runs inside the images. File
tools run inside the task container (`podman exec`, `realpath`-checked), so a
symlink the agent's commands plant never reaches the host. Graders run steps
A-G in a fresh `--network none` container that never saw the agent's.

| Module | Role |
|---|---|
| `session` | One run's state behind the tools: prepare, grade, finish |
| `tools` | The `defensive__*` `AgentTool`s |
| `task` | `/patch` stages for CVEs, GitHub repos and local folders |
| `audit` | `/audit` stages, corroboration and the findings report |
| `workspace` | The agent's sandbox tools |
| `grader` | The trusted graders (any language; Go/CVE with hidden tests) |
| `sandbox` | Images, containers, `podman exec` with time limits |
| `sources` | CVE/OSV records, git clones, local folders |
| `profiles` | Language detection: image, dependencies, build and test commands |
| `analyzers` | gosec, go vet, govulncheck, bandit, npm audit |
| `patchlib`, `scoring`, `report` | Diffs, the 12 checks, stage reports |

Tests: `cargo test -p loop-defensive`. With podman:
`cargo test -p loop-defensive --test e2e_podman -- --ignored`.
