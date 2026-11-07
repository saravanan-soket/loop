//! Defensive security workflows for Loop.
//!
//! - `/patch <CVE | github-url | folder>`: find a vulnerability, prove it with a
//!   failing test, patch it in a network-less podman sandbox, and have a trusted
//!   grader verify the fix in a fresh container.
//! - `/audit <github-url>`: review a repository and report corroborated
//!   findings, without patching.
//!
//! Every stage writes a report (`report.md`, `report.json`, one JSON file per
//! stage) under the runs directory. Repository code only ever runs inside
//! rootless podman with `--network none`.

pub mod analyzers;
pub mod grader;
pub mod patchlib;
pub mod profiles;
pub mod report;
pub mod sandbox;
pub mod sources;
pub mod task;
pub mod workspace;
pub mod scoring;
