//! Bounded ripgrep option grammar for read-only validation.
//! A `--` that is an option's value does not terminate option parsing.

const VALUE_OPTIONS: &[&str] = &[
    "regexp",
    "file",
    "pre-glob",
    "dfa-size-limit",
    "encoding",
    "engine",
    "max-count",
    "regex-size-limit",
    "threads",
    "glob",
    "iglob",
    "ignore-file",
    "max-depth",
    "max-filesize",
    "type",
    "type-not",
    "type-add",
    "type-clear",
    "after-context",
    "before-context",
    "color",
    "colors",
    "context",
    "context-separator",
    "field-context-separator",
    "field-match-separator",
    "hyperlink-format",
    "max-columns",
    "path-separator",
    "replace",
    "sort",
    "sortr",
    "generate",
];

const FLAG_OPTIONS: &[&str] = &[
    "search-zip",
    "case-sensitive",
    "crlf",
    "fixed-strings",
    "ignore-case",
    "invert-match",
    "line-regexp",
    "mmap",
    "multiline",
    "multiline-dotall",
    "unicode",
    "null-data",
    "pcre2",
    "smart-case",
    "stop-on-nonmatch",
    "text",
    "word-regexp",
    "auto-hybrid-regex",
    "pcre2-unicode",
    "binary",
    "follow",
    "hidden",
    "glob-case-insensitive",
    "ignore-file-case-insensitive",
    "ignore",
    "ignore-dot",
    "ignore-exclude",
    "ignore-files",
    "ignore-global",
    "ignore-parent",
    "ignore-vcs",
    "require-git",
    "one-file-system",
    "block-buffered",
    "byte-offset",
    "column",
    "heading",
    "help",
    "include-zero",
    "line-buffered",
    "line-number",
    "max-columns-preview",
    "null",
    "only-matching",
    "passthru",
    "pretty",
    "quiet",
    "trim",
    "vimgrep",
    "with-filename",
    "no-filename",
    "sort-files",
    "count",
    "count-matches",
    "files-with-matches",
    "files-without-match",
    "json",
    "debug",
    "ignore-messages",
    "messages",
    "stats",
    "trace",
    "files",
    "no-config",
    "pcre2-version",
    "type-list",
    "version",
    "no-pre",
];

pub(super) fn validate_arguments(args: &[String]) -> Result<(), &'static str> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        i += 1;
        if arg == "--" {
            return Ok(());
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, inline) = long
                .split_once('=')
                .map_or((long, false), |(name, _)| (name, true));
            if matches!(name, "pre" | "hostname-bin") {
                return Err("ripgrep external-program options are not allowed in read-only mode");
            }
            if VALUE_OPTIONS.contains(&name) {
                if !inline {
                    if i == args.len() {
                        return Err("ripgrep option is missing its value in read-only mode");
                    }
                    i += 1;
                }
            } else if !inline
                && (FLAG_OPTIONS.contains(&name)
                    || name
                        .strip_prefix("no-")
                        .is_some_and(|name| FLAG_OPTIONS.contains(&name)))
            {
                // Boolean flags have no separate value.
            } else {
                return Err("unsupported ripgrep option cannot be validated in read-only mode");
            }
        } else if arg.starts_with('-') && arg.len() > 1 {
            for (offset, flag) in arg[1..].char_indices() {
                if "efEmjgdtTABCMr".contains(flag) {
                    if arg[offset + 2..].is_empty() {
                        if i == args.len() {
                            return Err("ripgrep option is missing its value in read-only mode");
                        }
                        i += 1;
                    }
                    break;
                }
                if !"zsFivxUPSawL.ubhnNM0opqHIclV".contains(flag) {
                    return Err("unsupported ripgrep option cannot be validated in read-only mode");
                }
            }
        }
    }
    Ok(())
}
