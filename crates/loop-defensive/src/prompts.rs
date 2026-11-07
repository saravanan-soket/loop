//! The prompts `/patch` and `/audit` send, and the system prompts for
//! headless runs.

/// The `/patch <target>` prompt.
pub fn patch(target: &str) -> String {
    PATCH.replace("$1", target.trim())
}

/// The `/audit <url>` prompt.
pub fn audit(url: &str) -> String {
    AUDIT.replace("$1", url.trim())
}

const PATCH: &str = "\
Run the defensive workflow for $1 using only the `defensive__` tools (the built-in read, write, edit and bash tools are not available during this run).

$1 is a CVE id, a GitHub repository URL, or a local folder. Repositories and folders can be in any language; CVE ids must be Go projects.

1. Call `defensive__prepare_task` with target \"$1\". Show me the stage reports it prints. If it says the target cannot be worked on, explain why and stop.
2. Identify the bug: call `defensive__get_task`, then investigate with `defensive__list_directory`, `defensive__search_code` and `defensive__read_file` until you know the vulnerable code and its root cause.
   - For a CVE, the task describes the known vulnerability; find it in the code.
   - For a GitHub URL or local folder, no vulnerability is known in advance. Assess the code: call `defensive__run_analyzer` with \"all\" and confirm or dismiss each lead by reading the code, and map the untrusted-input entry points (HTTP handlers, form and URL input, DOM sinks such as innerHTML, parsers, deserialization, exec, SQL, file paths, auth, crypto, secrets) and where that data flows. Pick the most severe issue that untrusted input can actually reach. Tell me what you found and why you chose it before patching. If you find nothing real, say so and call `defensive__finish_task` instead of inventing a bug.
3. Reproduce it with a small test that FAILS on the current code, written with `defensive__write_file`:
   - Go: a new `*_test.go` file, run with `defensive__run_go` (for example `test ./<pkg> -run TestRepro -v`).
   - Any other language: a file in the project's test layout (for example `test/repro.test.js`, `tests/test_repro.py`, `spec/repro_spec.rb`, `src/test/java/.../ReproTest.java`, `tests/repro.rs`), run with `defensive__run_command`. `defensive__get_task` shows the language, build command and test command; use the project's own test framework when it has one, otherwise the language's built-in one (`node --test`, `python -m unittest`, a shell script for C).
   For a repo target this test is the grader's oracle, so it must check the security property itself, not an implementation detail of your fix.
4. Patch it: make a minimal change to non-test source files with `defensive__edit_file`. Do not change dependency manifests or lockfiles (go.mod, package.json, requirements.txt, Cargo.toml, ...).
5. Verify: re-run your reproduction test (it must now PASS), then run the project's existing tests (`defensive__run_go test ./<pkg>`, or the test command from `defensive__get_task` with `defensive__run_command`) to check for regressions. Use `defensive__show_diff` to review the change.
6. Report: call `defensive__submit_report` with the summary, root cause, affected files, vulnerable lines as `path:start-end`, the fix, and the exact before/after results of your test and the regression run. For a non-Go repo, also pass `repro_command`: the command that runs ONLY your reproduction test (non-zero exit while vulnerable, zero once fixed).
7. Call `defensive__grade_patch`. Show me its stage reports. If it is not verified, use its feedback, fix the code in the same workspace and call `defensive__grade_patch` again.
8. Finish with a short summary: the bug, the root cause, your fix, your verification, and the grader's verdict (and score, for a CVE). For a repo target, remind me that the verdict rests on your own reproduction test and the finding should be reviewed by a human. Tell me where the patch file is (`runs/.../attempt-N/candidate.patch`) so I can apply it to my copy; the original repository or folder was not modified.";

const AUDIT: &str = "\
Audit the GitHub repository $1 for security vulnerabilities and give me a report. Use only the `defensive__` tools (the built-in read, write, edit and bash tools are not available during this run). You are reporting vulnerabilities, not fixing them.

1. Call `defensive__prepare_audit` with url \"$1\". Show me the stage reports it prints. If it says the repo cannot be audited, explain why and stop.
2. Map the code: `defensive__list_directory` and `defensive__search_code` to find untrusted-input entry points (HTTP handlers, parsers, deserialization, exec, SQL, file paths, crypto) and where that data flows.
3. Call `defensive__run_analyzer` with \"all\" to get static-analyzer leads (Go: gosec, go vet, govulncheck; Python: Bandit). Confirm or dismiss each by reading the code with `defensive__read_file`; do not just repeat them.
4. For each real issue, call `defensive__submit_finding` with a title, severity, CWE, the file and line range you have read and verified, a description, the data flow (source to sink), the reachability (can untrusted input actually reach it, and under what conditions: this is the exploitability assessment), the impact, and a recommendation.
5. Call `defensive__submit_audit_report` with the summary, scope, methodology and overall risk.
6. Call `defensive__finish_audit`. Show me its report.
7. Summarize for me: the highest-severity issues, their reachability, and the overall risk. Remind me these are candidates for human review, not a verdict.";

#[cfg(test)]
mod tests {
    #[test]
    fn prompts_fill_the_target() {
        let p = super::patch(" https://github.com/o/r ");
        assert!(p.starts_with("Run the defensive workflow for https://github.com/o/r using"));
        assert!(!p.contains("$1"));
        assert!(!super::audit("https://github.com/o/r").contains("$1"));
    }
}
