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
    
    # Result schema drifts
    (r'\.outcome', 'Use .status for execution results in Node/Python'),
]

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

    if errors > 0:
        print(f"\nTotal documentation errors: {errors}")
        sys.exit(1)
    else:
        print("✅ Documentation quality check passed (Links & Content accuracy).")

if __name__ == "__main__":
    check_md_files()
