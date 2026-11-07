//! Sandboxed defensive workflows (`/patch`, `/audit`, see `loop-defensive`).
//!
//! While one runs, its `defensive__*` tools own the toolset: the gate offers
//! only them and runs them without asking, because they act inside a
//! network-less podman container on a copy of the code. Loop's own file and
//! shell tools come back when the run ends.

use std::sync::Arc;

use loop_agent::harness::AgentHarness;
pub use loop_defensive::{prompts, task::runs_root, Session, Workflow, PREFIX};

use crate::tool_gate::ToolGate;

/// Give `workflow`'s tools the toolset.
pub async fn begin(
    harness: &AgentHarness,
    gate: &ToolGate,
    session: &Arc<Session>,
    workflow: Workflow,
) -> anyhow::Result<()> {
    let mut tools: Vec<_> = harness
        .get_tools()
        .await
        .into_iter()
        .filter(|tool| !tool.name.starts_with(PREFIX))
        .collect();
    tools.extend(loop_defensive::tools::tools(session, workflow));
    harness
        .set_tools(tools)
        .await
        .map_err(|e| anyhow::anyhow!("set defensive tools: {e}"))?;
    gate.set_focus(Some(PREFIX.to_owned()));
    Ok(())
}

/// End the run: finish its report (if it was still going), stop its
/// container and give the toolset back. Returns the final stage output, if
/// any.
pub async fn end(harness: &AgentHarness, gate: &ToolGate, session: Option<&Arc<Session>>) -> String {
    let report = match session {
        Some(session) => {
            let session = Arc::clone(session);
            tokio::task::spawn_blocking(move || session.shutdown())
                .await
                .unwrap_or_default()
        }
        None => String::new(),
    };
    gate.set_focus(None);
    let tools: Vec<_> = harness
        .get_tools()
        .await
        .into_iter()
        .filter(|tool| !tool.name.starts_with(PREFIX))
        .collect();
    let _ = harness.set_tools(tools).await;
    report
}

/// Whether a defensive workflow owns the toolset.
pub fn active(gate: &ToolGate) -> bool {
    gate.focus().as_deref() == Some(PREFIX)
}
