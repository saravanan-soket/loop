//! End to end with real podman: `/patch` on a local folder, driven by a
//! scripted agent instead of a model. Needs rootless podman and network for
//! the image build, so it is ignored by default:
//!
//! `cargo test -p loop-defensive --test e2e_podman -- --ignored --nocapture`

use std::fs;
use std::path::Path;

use loop_defensive::Session;
use serde_json::{json, Value};

fn call(s: &Session, name: &str, args: Value) -> (Value, bool) {
    let (text, err) = s.call(name, &args);
    (serde_json::from_str(&text).unwrap_or(Value::String(text)), err)
}

fn project(dir: &Path) {
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(dir.join("package.json"), r#"{"name": "e2e", "version": "1.0.0"}"#).unwrap();
    // Path traversal: "../" is not rejected.
    fs::write(
        dir.join("src/paths.js"),
        "function isSafe(p) {\n  return !p.startsWith('/');\n}\nmodule.exports = { isSafe };\n",
    )
    .unwrap();
}

#[test]
#[ignore = "needs rootless podman and network"]
fn patch_a_local_folder_end_to_end() {
    let runs = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let s = Session::new(runs.path().into(), src.path().into());

    let ready = s.prepare_task(&src.path().to_string_lossy(), "");
    println!("{ready}");
    assert!(ready.contains("STAGE 0 RESOLVE — PASS"), "{ready}");
    assert!(ready.contains("STAGE 2 SANDBOX — PASS"), "{ready}");
    assert!(ready.contains("Sandbox ready"), "{ready}");
    assert!(s.in_progress());

    let (task, err) = call(&s, "get_task", json!({}));
    assert!(!err && task["mode"] == "repo", "{task}");
    let (ls, err) = call(&s, "list_directory", json!({}));
    assert!(!err && ls["entries"].as_array().unwrap().iter().any(|e| e == "src/"), "{ls}");
    let (read, _) = call(&s, "read_file", json!({"path": "src/paths.js", "start_line": 2, "end_line": 2}));
    assert_eq!(read["content"], "    2    return !p.startsWith('/');");
    let (hits, _) = call(&s, "search_code", json!({"pattern": "startsWith"}));
    assert_eq!(hits["matches"][0], "src/paths.js:2: return !p.startsWith('/');");

    // The sandbox boundaries.
    let (_, err) = call(&s, "write_file", json!({"path": ".defensive/x", "content": "x"}));
    assert!(err, "reserved location");
    let (_, err) = call(&s, "read_file", json!({"path": "../../etc/passwd"}));
    assert!(err, "relative escape");
    let (r, _) = call(&s, "run_command", json!({"command": "ln -s /etc/hostname leak && echo linked"}));
    assert_eq!(r["exit_code"], 0, "{r}");
    let (leak, err) = call(&s, "read_file", json!({"path": "leak"}));
    assert!(err && leak["error"].as_str().unwrap().contains("escapes"), "{leak}");
    let (net, _) = call(&s, "run_command", json!({"command": "getent hosts example.com || echo offline"}));
    assert!(net["output"].as_str().unwrap().contains("offline"), "{net}");
    call(&s, "run_command", json!({"command": "rm leak"}));

    // Reproduce, then fix.
    let test = "const test = require('node:test');\nconst assert = require('node:assert');\n\
                const { isSafe } = require('../src/paths');\n\
                test('rejects traversal', () => { assert.strictEqual(isSafe('../etc/passwd'), false); });\n";
    let (w, err) = call(&s, "write_file", json!({"path": "test/repro.test.js", "content": test}));
    assert!(!err && w["ok"] == true, "{w}");
    let (before, _) = call(&s, "run_command", json!({"command": "node --test test/repro.test.js"}));
    assert_ne!(before["exit_code"], 0, "{before}");
    let (e, _) = call(
        &s,
        "edit_file",
        json!({"path": "src/paths.js", "old_text": "return !p.startsWith('/');",
               "new_text": "return !p.startsWith('/') && !p.split('/').includes('..');"}),
    );
    assert_eq!(e["ok"], true, "{e}");
    let (after, _) = call(&s, "run_command", json!({"command": "node --test test/repro.test.js"}));
    assert_eq!(after["exit_code"], 0, "{after}");
    let (diff, _) = call(&s, "show_diff", json!({}));
    assert_eq!(diff["code_files"], json!(["src/paths.js"]));
    assert_eq!(diff["test_files"], json!(["test/repro.test.js"]));

    let (rep, err) = call(
        &s,
        "submit_report",
        json!({"summary": "path traversal", "root_cause": "isSafe only rejected absolute paths",
               "affected_files": ["src/paths.js"], "vulnerable_lines": "src/paths.js:1-3",
               "fix_description": "reject .. segments", "verification": "repro fails before, passes after",
               "repro_command": "node --test test/repro.test.js"}),
    );
    assert!(!err && rep["ok"] == true, "{rep}");

    let graded = s.grade_patch();
    println!("{graded}");
    assert!(graded.contains("verdict PATCH_VERIFIED"), "{graded}");
    assert!(graded.contains("STAGE 7 FINAL — PASS"), "{graded}");
    assert!(!s.in_progress());

    let run = fs::read_dir(runs.path().join("repo")).unwrap().next().unwrap().unwrap().path();
    let latest = run.join("latest");
    let md = fs::read_to_string(latest.join("report.md")).unwrap();
    assert!(md.contains("## Stage 6 grade (attempt 1): PASS"), "{md}");
    let patch = fs::read_to_string(latest.join("attempt-1/candidate.patch")).unwrap();
    assert!(patch.contains("+++ b/src/paths.js"), "{patch}");
    let report: Value = serde_json::from_str(&fs::read_to_string(latest.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["lifecycle"], "PATCH_VERIFIED");
    assert_eq!(report["best"], json!({"attempt": 1, "final_status": "PATCH_VERIFIED"}));
    // The original folder was not modified.
    assert!(fs::read_to_string(src.path().join("src/paths.js")).unwrap().contains("return !p.startsWith('/');\n"));
    assert!(!src.path().join("test").exists());
}

#[test]
#[ignore = "needs rootless podman and network"]
fn a_wrong_fix_is_not_verified() {
    let runs = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let s = Session::new(runs.path().into(), src.path().into());
    assert!(s.prepare_task(&src.path().to_string_lossy(), "").contains("Sandbox ready"));
    let test = "const test = require('node:test');\nconst assert = require('node:assert');\n\
                const { isSafe } = require('../src/paths');\n\
                test('rejects traversal', () => { assert.strictEqual(isSafe('../x'), false); });\n";
    call(&s, "write_file", json!({"path": "test/repro.test.js", "content": test}));
    // A "fix" that does not fix it.
    call(&s, "edit_file", json!({"path": "src/paths.js", "old_text": "return", "new_text": "// noop\n  return"}));
    call(
        &s,
        "submit_report",
        json!({"summary": "s", "root_cause": "r", "affected_files": ["src/paths.js"], "vulnerable_lines": "src/paths.js:1-2",
               "fix_description": "f", "verification": "v", "repro_command": "node --test test/repro.test.js"}),
    );
    let graded = s.grade_patch();
    println!("{graded}");
    assert!(graded.contains("verdict REPRODUCIBLE"), "{graded}");
    assert!(graded.contains("Not verified: your reproduction test still fails on the patched code"), "{graded}");
    assert!(s.in_progress(), "attempts remain");
    let finished = s.finish_task();
    assert!(finished.contains("STAGE 7 FINAL"), "{finished}");
    assert!(!s.in_progress());
}
