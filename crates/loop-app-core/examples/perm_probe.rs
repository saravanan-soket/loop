// Probe permission edge cases against the real Loop code
fn main() {
    let danger = ["rm", "-rf"].join(" ");
    let cases = [
        format!("ls | xargs {danger}"),
        format!("cat file | tee /etc/passwd"),
        format!("echo hi && env {danger} x"),
        "find . -name '*.rs' -exec chmod +x {} +".to_string(),
        "git log --output=/tmp/x".to_string(),
        format!("ls\n{danger} /"),
        format!("ls ; {danger} /"),
        format!("echo 'safe' # {danger} /"),
        "ls --color=always".to_string(),
        "grep -r pattern . --include='*.rs'".to_string(),
        // read-only classification probes
        "ls | xargs cat".to_string(),
        "git status | sh".to_string(),
        "cat a b; echo done".to_string(),
    ];
    for c in &cases {
        let parts = loop_app_core::permissions::split_command(c);
        let ro = loop_app_core::permissions::read_only_command(c);
        println!("{:60} parts={parts:?} read_only={ro}", format!("{:?}", c));
    }
}
