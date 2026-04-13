import os
import re
import sys

# ── Content Linting Rules ───────────────────────────────────────────────────
# These patterns help catch common drifts between implementation and documentation.

STALE_PATTERNS = [
    # API naming drifts
    (r'Guard::from_file', 'Use Guard::from_yaml_file instead'),
    
    # Configuration key drifts
    (r'audit:\s+enabled:.*?\s+path:', 'Use file_path instead of path in audit config'),
    
    # Policy schema drifts
    (r'rules:\s+- tool:', 'Use tools: map instead of rules: list in policy YAML'),
    
    # Maturity status drifts
    (r'Python/Node\.js Bindings.*?Coming soon', 'Bindings are already available'),
    
    # Security promise drifts
    (r'every (tool call|execution) (automatically )?generates (a |an )?signed receipt', 'Receipts are supported/optional and require an explicit signing key'),
    (r'tamper-evident.*?audit log', 'Only Signed Receipts are tamper-evident, not local JSONL logs'),
    (r'non-repudiab(?:le|ility)\s+(?:JSONL\s+)?audit log', 'Local JSONL logs are forensic records; only signed receipts provide cryptographic provenance'),
    (r'(?:JSONL\s+)?audit log[s]?\s+(?:are|is)\s+non-repudiab(?:le|ility)', 'Local JSONL logs are forensic records; only signed receipts provide cryptographic provenance'),
    (r'Seccomp-BPF.*?Production Ready', 'Linux Seccomp-BPF is not production-ready in v0.2.0; current Linux baseline is prototype/fallback'),
    (r'full kernel-level syscall filtering on Linux', 'Current Linux sandboxing does not provide full Seccomp-BPF syscall filtering'),
    (r'\|\s+\*\*`filesystem_write_global`\*\*\s+\|\s+🛡️ Blocked\s+\|', 'Linux prototype fallback does not block global writes in the capability matrix'),
    (r'\|\s+\*\*`network_outbound_any`\*\*\s+\|\s+🛡️ Blocked\s+\|', 'Linux prototype fallback does not block outbound network access in the capability matrix'),
    (r'global filesystem write protection \(Prototype\)', 'Linux prototype fallback does not currently guarantee global write protection'),
    (r'While Seccomp blocks writes globally', 'Current Linux prototype fallback does not yet block writes globally'),
    (r'provides OS-level process isolation on Linux using `seccomp-bpf`', 'The Linux sandbox doc should describe the current prototype wrapper, not shipped seccomp-bpf enforcement'),
    
    # Result schema drifts
    (r'\.outcome', 'Use .status for execution results in Node/Python'),
]

FENCED_BLOCK_PATTERN = re.compile(r"```(?P<lang>[A-Za-z0-9_+-]*)\n(?P<body>.*?)```", re.DOTALL)


def extract_fenced_blocks(content):
    for match in FENCED_BLOCK_PATTERN.finditer(content):
        yield match.group("lang").strip().lower(), match.group("body")


def check_yaml_block(block, rel_path):
    errors = 0

    if re.search(r"(?m)^working_directory:\s*", block):
        print(f"❌ Invalid policy example in {rel_path}: top-level 'working_directory' is not a policy key")
        print("   👉 Suggestion: Set working_directory in execution Context, not in policy YAML")
        errors += 1

    return errors


def check_rust_block(block, rel_path):
    errors = 0

    if "GuardInput {" in block:
        has_explicit_import = re.search(r"use\s+agent_guard_sdk::GuardInput\s*;", block)
        has_grouped_import = re.search(r"use\s+agent_guard_sdk::\{[^}]*\bGuardInput\b[^}]*\};", block, re.DOTALL)
        if not (has_explicit_import or has_grouped_import):
            print(f"❌ Rust snippet issue in {rel_path}: GuardInput is used but not imported")
            print("   👉 Suggestion: Add GuardInput to the agent_guard_sdk import list")
            errors += 1

    return errors


def check_md_files():
    root_dir = os.getcwd()
    md_files = []
    for root, dirs, files in os.walk(root_dir):
        if 'target' in root or '.git' in root or 'node_modules' in root:
            continue
        for file in files:
            if file.endswith('.md'):
                md_files.append(os.path.join(root, file))

    errors = 0
    link_pattern = re.compile(r'\[.*?\]\((?P<path>.*?)\)')

    print(f"🔍 Scanning {len(md_files)} markdown files for quality gate violations...")

    for md_file in md_files:
        rel_path = os.path.relpath(md_file, root_dir)
        with open(md_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # 1. Check Internal Links
            links = link_pattern.findall(content)
            current_dir = os.path.dirname(md_file)
            for link in links:
                if link.startswith('http') or link.startswith('#') or link.startswith('mailto:'):
                    continue
                path = link.split('#')[0]
                if not path: continue
                target_path = os.path.abspath(os.path.join(current_dir, path))
                if not os.path.exists(target_path):
                    print(f"❌ Broken link in {rel_path}: '{link}'")
                    errors += 1

            # 2. Check for Stale Patterns
            for pattern, suggestion in STALE_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                    print(f"❌ Stale/Misleading content in {rel_path}: matching '{pattern}'")
                    print(f"   👉 Suggestion: {suggestion}")
                    errors += 1

            # 3. Check fenced code blocks for common integration mistakes
            for lang, block in extract_fenced_blocks(content):
                if lang in {"yaml", "yml"}:
                    errors += check_yaml_block(block, rel_path)
                elif lang == "rust":
                    errors += check_rust_block(block, rel_path)

    if errors > 0:
        print(f"\nTotal documentation errors: {errors}")
        sys.exit(1)
    else:
        print("✅ Documentation quality check passed (Links & Content accuracy).")

if __name__ == "__main__":
    check_md_files()
