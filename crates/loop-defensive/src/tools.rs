//! The `defensive__*` agent tools.

use std::sync::Arc;

use loop_agent::types::{AgentTool, AgentToolResult};
use serde_json::{json, Value};

use crate::session::Session;

/// Prefix of every defensive tool name.
pub const PREFIX: &str = "defensive__";

/// Which workflow a toolset serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Workflow {
    /// `/patch`.
    Patch,
    /// `/audit`.
    Audit,
}

fn schema(props: Value, required: &[&str]) -> Value {
    json!({"type": "object", "properties": props, "required": required})
}

fn specs(workflow: Workflow) -> Vec<(&'static str, &'static str, Value)> {
    let s = json!({"type": "string"});
    let i = json!({"type": "integer"});
    let a = json!({"type": "array", "items": {"type": "string"}});
    let common_read = [
        ("list_directory", "List a directory of the source (in the sandbox).", schema(json!({"path": s}), &[])),
        (
            "read_file",
            "Read a source file with line numbers (optional line range).",
            schema(json!({"path": s, "start_line": i, "end_line": i}), &["path"]),
        ),
        (
            "search_code",
            "Regex search across the source.",
            schema(json!({"pattern": s, "path": s, "max_results": i}), &["pattern"]),
        ),
    ];
    match workflow {
        Workflow::Patch => {
            let mut v = vec![(
                "prepare_task",
                "Set up a task and its podman sandbox. `target` is a CVE id (resolve it, fetch the vulnerable source, \
                 confirm the bug reproduces), a GitHub repo URL (optionally .../tree/<ref>) or a path to a local folder \
                 (copied into the sandbox; the original is never modified). Prints a report per stage.",
                schema(json!({"target": s, "ref": s}), &["target"]),
            )];
            v.push(("get_task", "Public facts about the task: the vulnerability or repository, language, build and test commands.", schema(json!({}), &[])));
            v.extend(common_read);
            v.extend([
                (
                    "write_file",
                    "Create or overwrite a file, e.g. a reproduction test.",
                    schema(json!({"path": s, "content": s}), &["path", "content"]),
                ),
                (
                    "edit_file",
                    "Replace one exact occurrence of old_text with new_text.",
                    schema(json!({"path": s, "old_text": s, "new_text": s}), &["path", "old_text", "new_text"]),
                ),
                (
                    "run_go",
                    "Run `go build|test|vet|list <args>` in the sandbox, e.g. 'test . -run TestRepro -v'.",
                    schema(json!({"args": s}), &["args"]),
                ),
                (
                    "run_command",
                    "Run a shell command in the workspace inside the sandbox (no network), for non-Go projects: the \
                     reproduction test, the build, the test suite. Dependencies were installed when the sandbox was built.",
                    schema(json!({"command": s}), &["command"]),
                ),
                (
                    "run_analyzer",
                    "Static analyzers over the workspace (gosec | go_vet | govulncheck | bandit | npm_audit | all); \
                     normalized leads to confirm or dismiss.",
                    schema(json!({"tool": s}), &[]),
                ),
                ("show_diff", "Your changes versus the original source.", schema(json!({}), &[])),
                (
                    "submit_report",
                    "Submit the root-cause report (before grade_patch).",
                    schema(
                        json!({"summary": s, "root_cause": s, "affected_files": a, "vulnerable_lines": s,
                               "fix_description": s, "verification": s,
                               "repro_command": {"type": "string", "description":
                                   "Non-Go repo targets: shell command that runs ONLY your reproduction test (non-zero exit = vulnerable)."},
                               "test_command": {"type": "string", "description":
                                   "Optional: override the project's test-suite command."}}),
                        &["summary", "root_cause", "affected_files", "vulnerable_lines", "fix_description", "verification"],
                    ),
                ),
                (
                    "grade_patch",
                    "Stage 6: the trusted grader rebuilds your patch in a fresh container and runs the security tests \
                     (hidden ones for a CVE; your own reproduction test for a repo) plus the existing tests. Prints the \
                     verdict report.",
                    schema(json!({}), &[]),
                ),
                ("finish_task", "Write the final report and stop the sandbox (use if giving up).", schema(json!({}), &[])),
            ]);
            v
        }
        Workflow::Audit => {
            let mut v = vec![(
                "prepare_audit",
                "Stages 0-3 for a GitHub repo URL: clone at a pinned commit, build the audit sandbox, run the baseline \
                 static scan. Prints a report per stage.",
                schema(json!({"url": s, "ref": s}), &["url"]),
            )];
            v.push(("get_task", "Public facts about the repository under audit.", schema(json!({}), &[])));
            v.extend(common_read);
            v.extend([
                (
                    "run_analyzer",
                    "Run a static analyzer (gosec | go_vet | govulncheck | bandit | all); normalized findings.",
                    schema(json!({"tool": s}), &[]),
                ),
                ("run_go", "Run `go build|test|vet|list <args>` in the sandbox (no network).", schema(json!({"args": s}), &["args"])),
                (
                    "submit_finding",
                    "Record ONE finding: title, severity, cwe, file, start_line, end_line, description, data_flow, \
                     reachability (exploitability), impact, recommendation.",
                    schema(
                        json!({"title": s, "severity": s, "cwe": s, "file": s, "start_line": i, "end_line": i,
                               "description": s, "data_flow": s, "reachability": s, "impact": s,
                               "recommendation": s, "evidence": s}),
                        &["title", "severity", "cwe", "file", "start_line", "end_line", "description", "data_flow",
                          "reachability", "impact", "recommendation"],
                    ),
                ),
                (
                    "submit_audit_report",
                    "Record the overview (summary, scope, methodology, overall_risk).",
                    schema(json!({"summary": s, "scope": s, "methodology": s, "overall_risk": s}), &["summary", "scope", "methodology", "overall_risk"]),
                ),
                ("finish_audit", "Corroborate the findings and write the final report.", schema(json!({}), &[])),
            ]);
            v
        }
    }
}

/// The tools for `workflow`, all backed by `session`.
pub fn tools(session: &Arc<Session>, workflow: Workflow) -> Vec<AgentTool> {
    specs(workflow)
        .into_iter()
        .map(|(name, description, parameters)| {
            let session = Arc::clone(session);
            let full = format!("{PREFIX}{name}");
            AgentTool::simple(full.clone(), full, description, parameters, move |_id, args, _cancel, _update| {
                let session = Arc::clone(&session);
                async move {
                    let (text, is_error) = tokio::task::spawn_blocking(move || session.call(name, &args))
                        .await
                        .map_err(|e| format!("defensive tool failed: {e}"))?;
                    if is_error {
                        Err(text)
                    } else {
                        Ok(AgentToolResult::text(text))
                    }
                }
            })
        })
        .collect()
}

/// Tool names for `workflow`, prefixed.
pub fn names(workflow: Workflow) -> Vec<String> {
    specs(workflow).into_iter().map(|(n, _, _)| format!("{PREFIX}{n}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toolsets_are_prefixed_and_distinct() {
        let patch = names(Workflow::Patch);
        assert!(patch.iter().all(|n| n.starts_with(PREFIX)));
        assert!(patch.contains(&"defensive__grade_patch".to_owned()));
        assert!(!patch.contains(&"defensive__submit_finding".to_owned()));
        let audit = names(Workflow::Audit);
        assert!(audit.contains(&"defensive__finish_audit".to_owned()));
        assert!(!audit.iter().any(|n| n.ends_with("write_file") || n.ends_with("edit_file") || n.ends_with("run_command")));
        for (_, _, params) in specs(Workflow::Patch).into_iter().chain(specs(Workflow::Audit)) {
            assert_eq!(params["type"], "object");
        }
    }

    #[tokio::test]
    async fn tool_reports_missing_task_as_error() {
        let dir = tempfile::tempdir().unwrap();
        let session = Arc::new(Session::new(dir.path().into(), dir.path().into()));
        let read = tools(&session, Workflow::Patch).into_iter().find(|t| t.name == "defensive__read_file").unwrap();
        let err = (read.execute)("1".into(), json!({"path": "x"}), None, None).await.unwrap_err();
        assert!(err.contains("prepare_task"), "{err}");
    }
}
