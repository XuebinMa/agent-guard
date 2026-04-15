use agent_guard_sdk::{
    collect_doctor_report, load_policy_signature_file, load_public_key_file, parse_hex_signing_key,
    render_doctor_html, render_doctor_text, sign_policy, verify_policy, ExecutionReceipt,
};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};

/// CLI tool to verify agent-guard execution receipts and trust artifacts.
#[derive(Parser)]
#[command(name = "guard-verify", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify an execution receipt against a public key.
    Verify {
        /// Path to the receipt JSON file.
        #[arg(short, long)]
        receipt: PathBuf,
        /// Ed25519 public key: 64 hex chars, or path to a .pub file containing hex.
        #[arg(short, long)]
        public_key: String,
    },
    /// Inspect a receipt without verifying its signature.
    Inspect {
        /// Path to the receipt JSON file.
        #[arg(short, long)]
        receipt: PathBuf,
    },
    /// Generate a new Ed25519 keypair for receipt signing.
    Keygen {
        /// Write the private key (hex) to this file. If omitted, prints to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Sign a policy YAML file with a detached Ed25519 signature.
    SignPolicy {
        /// Path to the policy YAML file.
        #[arg(short, long)]
        policy: PathBuf,
        /// Ed25519 private key: 64 hex chars, or path to a file containing hex.
        #[arg(short = 'k', long)]
        private_key: String,
        /// Write the detached signature (hex) to this file. If omitted, prints to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a detached policy signature.
    VerifyPolicy {
        /// Path to the policy YAML file.
        #[arg(short, long)]
        policy: PathBuf,
        /// Detached signature hex, or path to a file containing it.
        #[arg(short, long)]
        signature: String,
        /// Ed25519 public key: 64 hex chars, or path to a file containing it.
        #[arg(short, long)]
        public_key: String,
    },
    /// Generate a CapabilityDoctor report in text, JSON, or HTML.
    Doctor {
        /// Output format for the report.
        #[arg(short, long, default_value = "text")]
        format: DoctorFormat,
        /// Optional output path. When omitted, writes to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum DoctorFormat {
    Text,
    Json,
    Html,
}

fn load_receipt(path: &PathBuf) -> Result<ExecutionReceipt, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read receipt file '{}': {}", path.display(), e))?;
    serde_json::from_str(&contents).map_err(|e| format!("Failed to parse receipt JSON: {}", e))
}

fn load_public_key(input: &str) -> Result<[u8; 32], String> {
    let hex_str = if Path::new(input).exists() {
        load_public_key_file(input)?
    } else {
        input.trim().to_string()
    };

    let bytes =
        hex::decode(hex_str.trim()).map_err(|e| format!("Invalid public key hex: {}", e))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        format!(
            "Public key must be 32 bytes (64 hex chars), got {} bytes",
            v.len()
        )
    })
}

fn load_private_key(input: &str) -> Result<SigningKey, String> {
    let hex_str = if Path::new(input).exists() {
        std::fs::read_to_string(input)
            .map_err(|e| format!("Failed to read private key file '{}': {}", input, e))?
    } else {
        input.to_string()
    };

    parse_hex_signing_key(hex_str.trim())
}

fn cmd_verify(receipt_path: &PathBuf, public_key_input: &str) {
    let receipt = match load_receipt(receipt_path) {
        Ok(r) => r,
        Err(e) => exit_with_error(&e),
    };

    let public_key = match load_public_key(public_key_input) {
        Ok(k) => k,
        Err(e) => exit_with_error(&e),
    };

    println!("Receipt: {}", receipt_path.display());
    println!("Agent:   {}", receipt.agent_id);
    println!("Tool:    {}", receipt.tool);
    println!("Policy:  {}", receipt.policy_version);
    println!("Sandbox: {}", receipt.sandbox_type);
    println!("Decision:{}", receipt.decision);
    println!("Time:    {}", format_timestamp(receipt.timestamp));
    println!();

    if receipt.verify(&public_key) {
        println!("RESULT:  PASS - Signature is valid.");
    } else {
        println!("RESULT:  FAIL - Signature verification failed.");
        std::process::exit(1);
    }
}

fn cmd_inspect(receipt_path: &PathBuf) {
    let receipt = match load_receipt(receipt_path) {
        Ok(r) => r,
        Err(e) => exit_with_error(&e),
    };

    println!("--- Execution Receipt ---");
    println!("Version:      {}", receipt.receipt_version);
    println!("Agent ID:     {}", receipt.agent_id);
    println!("Tool:         {}", receipt.tool);
    println!("Policy Ver:   {}", receipt.policy_version);
    println!("Sandbox Type: {}", receipt.sandbox_type);
    println!("Decision:     {}", receipt.decision);
    println!("Command Hash: {}", receipt.command_hash);
    println!(
        "Timestamp:    {} ({})",
        receipt.timestamp,
        format_timestamp(receipt.timestamp)
    );
    println!("Signature:    {}", signature_preview(&receipt.signature));
    println!("---");
    println!("Note: Use 'guard-verify verify' to validate the signature.");
}

fn cmd_keygen(output: &Option<PathBuf>) {
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(verifying_key.to_bytes());

    if let Some(path) = output {
        std::fs::write(path, &private_hex).unwrap_or_else(|e| {
            exit_with_error(&format!(
                "Failed to write private key to '{}': {}",
                path.display(),
                e
            ))
        });
        println!("Private key written to: {}", path.display());
    } else {
        println!("Private key (hex): {}", private_hex);
    }
    println!("Public key  (hex): {}", public_hex);
    println!();
    println!("Usage:");
    println!(
        "  1. Set signing key:  guard.load_signing_key_file(\"{}\")",
        output
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<key-file>".to_string())
    );
    println!(
        "  2. Verify receipts:  guard-verify verify --receipt <file> --public-key {}",
        public_hex
    );
    println!(
        "  3. Sign policy:      guard-verify sign-policy --policy policy.yaml --private-key {}",
        output
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<key-file>".to_string())
    );
}

fn cmd_sign_policy(policy_path: &PathBuf, private_key_input: &str, output: &Option<PathBuf>) {
    let yaml = std::fs::read_to_string(policy_path).unwrap_or_else(|e| {
        exit_with_error(&format!(
            "Failed to read policy file '{}': {}",
            policy_path.display(),
            e
        ))
    });
    let signing_key = load_private_key(private_key_input).unwrap_or_else(|e| exit_with_error(&e));
    let signature = sign_policy(&yaml, &signing_key);

    if let Some(path) = output {
        std::fs::write(path, &signature).unwrap_or_else(|e| {
            exit_with_error(&format!(
                "Failed to write signature to '{}': {}",
                path.display(),
                e
            ))
        });
        println!("Policy signature written to: {}", path.display());
    } else {
        println!("{}", signature);
    }
}

fn cmd_verify_policy(policy_path: &PathBuf, signature_input: &str, public_key_input: &str) {
    let yaml = std::fs::read_to_string(policy_path).unwrap_or_else(|e| {
        exit_with_error(&format!(
            "Failed to read policy file '{}': {}",
            policy_path.display(),
            e
        ))
    });
    let signature_hex = if Path::new(signature_input).exists() {
        load_policy_signature_file(signature_input).unwrap_or_else(|e| exit_with_error(&e))
    } else {
        signature_input.trim().to_string()
    };
    let public_key_hex = if Path::new(public_key_input).exists() {
        load_public_key_file(public_key_input).unwrap_or_else(|e| exit_with_error(&e))
    } else {
        public_key_input.trim().to_string()
    };

    let verification = verify_policy(&yaml, &public_key_hex, &signature_hex);
    println!("Policy: {}", policy_path.display());
    println!("Status: {}", verification.status_label());
    if let Some(error) = &verification.error {
        println!("Error:  {}", error);
    }
    if verification.is_verified() {
        println!("RESULT: PASS - Policy signature is valid.");
    } else {
        println!("RESULT: FAIL - Policy signature verification failed.");
        std::process::exit(1);
    }
}

fn cmd_doctor(format: DoctorFormat, output: &Option<PathBuf>) {
    let report = collect_doctor_report();
    let rendered = match format {
        DoctorFormat::Text => render_doctor_text(&report),
        DoctorFormat::Json => serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
            exit_with_error(&format!("Failed to serialize doctor report: {e}"))
        }),
        DoctorFormat::Html => render_doctor_html(&report),
    };

    if let Some(path) = output {
        std::fs::write(path, rendered).unwrap_or_else(|e| {
            exit_with_error(&format!(
                "Failed to write doctor report to '{}': {}",
                path.display(),
                e
            ))
        });
        println!("Doctor report written to: {}", path.display());
    } else {
        println!("{}", rendered);
    }
}

fn format_timestamp(ts: u64) -> String {
    chrono::DateTime::from_timestamp(ts as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "invalid timestamp".to_string())
}

fn signature_preview(signature: &str) -> String {
    const EDGE_LEN: usize = 16;

    if signature.is_empty() {
        return "<empty>".to_string();
    }

    if signature.len() <= EDGE_LEN * 2 {
        return signature.to_string();
    }

    format!(
        "{}...{}",
        &signature[..EDGE_LEN],
        &signature[signature.len() - EDGE_LEN..]
    )
}

fn exit_with_error(message: &str) -> ! {
    eprintln!("ERROR: {}", message);
    std::process::exit(1);
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Verify {
            receipt,
            public_key,
        } => cmd_verify(receipt, public_key),
        Commands::Inspect { receipt } => cmd_inspect(receipt),
        Commands::Keygen { output } => cmd_keygen(output),
        Commands::SignPolicy {
            policy,
            private_key,
            output,
        } => cmd_sign_policy(policy, private_key, output),
        Commands::VerifyPolicy {
            policy,
            signature,
            public_key,
        } => cmd_verify_policy(policy, signature, public_key),
        Commands::Doctor { format, output } => cmd_doctor(format.clone(), output),
    }
}

#[cfg(test)]
mod tests {
    use super::{load_private_key, signature_preview};
    use agent_guard_sdk::{sign_policy, verify_policy};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn signature_preview_handles_empty_string() {
        assert_eq!(signature_preview(""), "<empty>");
    }

    #[test]
    fn signature_preview_keeps_short_signatures_intact() {
        assert_eq!(signature_preview("abcd1234"), "abcd1234");
    }

    #[test]
    fn signature_preview_truncates_long_signatures() {
        let sig = "1234567890abcdef1234567890abcdeffeedfacecafebeef0011223344556677";
        assert_eq!(
            signature_preview(sig),
            "1234567890abcdef...0011223344556677"
        );
    }

    #[test]
    fn load_private_key_accepts_inline_hex() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let private_key_hex = hex::encode(signing_key.to_bytes());
        let parsed = load_private_key(&private_key_hex).expect("key should parse");
        assert_eq!(parsed.to_bytes(), signing_key.to_bytes());
    }

    #[test]
    fn sign_and_verify_policy_round_trip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let policy = "version: 1\ndefault_mode: workspace_write\n";
        let signature = sign_policy(policy, &signing_key);
        let verification = verify_policy(
            policy,
            &hex::encode(signing_key.verifying_key().to_bytes()),
            &signature,
        );
        assert!(verification.is_verified());
    }
}
