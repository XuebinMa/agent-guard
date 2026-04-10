use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// CLI tool to verify agent-guard execution receipts.
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExecutionReceipt {
    pub receipt_version: String,
    pub agent_id: String,
    pub tool: String,
    pub policy_version: String,
    pub sandbox_type: String,
    pub decision: String,
    pub command_hash: String,
    pub timestamp: u64,
    pub signature: String,
}

impl ExecutionReceipt {
    fn to_signing_payload(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            self.receipt_version,
            self.agent_id,
            self.tool,
            self.policy_version,
            self.sandbox_type,
            self.decision,
            self.command_hash,
            self.timestamp
        )
    }

    fn verify(&self, public_key_bytes: &[u8; 32]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key_bytes) else {
            return false;
        };
        let Ok(signature_bytes) = hex::decode(&self.signature) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&signature_bytes) else {
            return false;
        };
        let message = self.to_signing_payload();
        verifying_key.verify(message.as_bytes(), &signature).is_ok()
    }
}

fn load_receipt(path: &PathBuf) -> Result<ExecutionReceipt, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read receipt file '{}': {}", path.display(), e))?;
    serde_json::from_str(&contents).map_err(|e| format!("Failed to parse receipt JSON: {}", e))
}

fn load_public_key(input: &str) -> Result<[u8; 32], String> {
    // Try as a file path first
    let hex_str = if std::path::Path::new(input).exists() {
        std::fs::read_to_string(input)
            .map_err(|e| format!("Failed to read public key file '{}': {}", input, e))?
    } else {
        input.to_string()
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

fn cmd_verify(receipt_path: &PathBuf, public_key_input: &str) {
    let receipt = match load_receipt(receipt_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }
    };

    let public_key = match load_public_key(public_key_input) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }
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
        Err(e) => {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }
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
            eprintln!(
                "ERROR: Failed to write private key to '{}': {}",
                path.display(),
                e
            );
            std::process::exit(1);
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

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Verify {
            receipt,
            public_key,
        } => cmd_verify(receipt, public_key),
        Commands::Inspect { receipt } => cmd_inspect(receipt),
        Commands::Keygen { output } => cmd_keygen(output),
    }
}

#[cfg(test)]
mod tests {
    use super::signature_preview;

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
}
