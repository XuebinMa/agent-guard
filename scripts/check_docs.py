import os
import re
import sys

def check_links():
    root_dir = os.getcwd()
    md_files = []
    for root, dirs, files in os.walk(root_dir):
        if 'target' in root or '.git' in root:
            continue
        for file in files:
            if file.endswith('.md'):
                md_files.append(os.path.join(root, file))

    errors = 0
    link_pattern = re.compile(r'\[.*?\]\((?P<path>.*?)\)')

    for md_file in md_files:
        with open(md_file, 'r', encoding='utf-8') as f:
            content = f.read()
            links = link_pattern.findall(content)
            current_dir = os.path.dirname(md_file)
            
            for link in links:
                if link.startswith('http') or link.startswith('#') or link.startswith('mailto:'):
                    continue
                
                # Clean up anchors
                path = link.split('#')[0]
                if not path:
                    continue
                
                target_path = os.path.abspath(os.path.join(current_dir, path))
                if not os.path.exists(target_path):
                    print(f"❌ Broken link in {os.path.relpath(md_file, root_dir)}: '{link}' -> Target not found")
                    errors += 1

    if errors > 0:
        print(f"\nTotal broken links: {errors}")
        sys.exit(1)
    else:
        print("✅ All internal links verified successfully.")

if __name__ == "__main__":
    check_links()
