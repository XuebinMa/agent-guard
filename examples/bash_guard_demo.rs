use agent_guard::{
    check_destructive, classify_intent, validate_mode, validate_paths,
    validate_read_only, validate_sed, CommandIntent, PermissionMode, ValidationResult,
};
use std::path::Path;

fn main() {
    println!("=== Agent Guard - Bash Guard Demo ===\n");

    let commands = vec![
        "ls -la",
        "cat README.md",
        "grep -r 'pattern' src/",
        "git status",
        "git commit -m 'fix'",
        "rm -rf /tmp/test",
        "rm -rf /",
        "rm -rf *",
        "chmod -R 777 /",
        "dd if=/dev/zero of=/dev/sda",
        ":(){ :|:& };:",
        "curl https://example.com",
        "sudo apt-get install vim",
        "cat file.txt > output.txt",
        "sed -i 's/foo/bar/' file.txt",
        "shred /dev/sda",
    ];

    println!("--- Command Intent Classification ---");
    for cmd in &commands {
        let intent = classify_intent(cmd);
        let icon = match intent {
            CommandIntent::ReadOnly => "📖",
            CommandIntent::Write => "✏️",
            CommandIntent::Destructive => "💥",
            CommandIntent::Network => "🌐",
            CommandIntent::ProcessManagement => "⚙️",
            CommandIntent::PackageManagement => "📦",
            CommandIntent::SystemAdmin => "🔐",
            CommandIntent::Unknown => "❓",
        };
        println!("  {icon} [{intent:?}] {cmd}");
    }

    println!("\n--- ReadOnly Mode Validation ---");
    for cmd in &commands {
        let result = validate_read_only(cmd, PermissionMode::ReadOnly);
        match &result {
            ValidationResult::Allow => println!("  ✅ {cmd}"),
            ValidationResult::Block { reason } => println!("  ❌ {cmd}\n     {reason}"),
            ValidationResult::Warn { message } => println!("  ⚠️  {cmd}\n     {message}"),
        }
    }

    println!("\n--- Destructive Command Check ---");
    let dangerous = vec![
        "rm -rf /",
        "rm -rf ~",
        "mkfs.ext4 /dev/sda",
        "dd if=/dev/zero of=/dev/sda",
        ":(){ :|:& };:",
        "shred /dev/sda",
        "ls -la",
    ];
    for cmd in &dangerous {
        let result = check_destructive(cmd);
        match &result {
            ValidationResult::Allow => println!("  ✅ Safe: {cmd}"),
            ValidationResult::Warn { message } => println!("  ⚠️  DANGER: {cmd}\n     {message}"),
            ValidationResult::Block { reason } => println!("  ❌ Blocked: {cmd}\n     {reason}"),
        }
    }

    println!("\n--- Path Traversal Detection ---");
    let workspace = Path::new("/workspace");
    let path_cmds = vec![
        "cat /workspace/src/main.rs",
        "rm ../../../etc/passwd",
        "cat ~/secret/.env",
        "ls $HOME/.ssh",
    ];
    for cmd in &path_cmds {
        let result = validate_paths(cmd, workspace);
        match &result {
            ValidationResult::Allow => println!("  ✅ {cmd}"),
            ValidationResult::Warn { message } => println!("  ⚠️  {cmd}\n     {message}"),
            ValidationResult::Block { reason } => println!("  ❌ {cmd}\n     {reason}"),
        }
    }
}
