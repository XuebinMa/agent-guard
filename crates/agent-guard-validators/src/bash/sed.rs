//! A deliberately bounded sed grammar for restricted shell modes.
//! Script files and commands with secondary I/O/execution cannot be inferred
//! from the input filenames; unsupported syntax therefore fails closed.

#[derive(Debug, Default)]
pub(super) struct SedInvocation {
    pub in_place: bool,
    pub files: Vec<String>,
}

pub(super) fn parse(args: &[String]) -> Result<SedInvocation, &'static str> {
    let mut result = SedInvocation::default();
    let mut scripts = Vec::new();
    let mut operands = Vec::new();
    let mut options = true;
    let mut i = 0;
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "--version") {
        return Ok(result);
    }
    while i < args.len() {
        let arg = args[i].as_str();
        i += 1;
        if options && arg == "--" {
            options = false;
            continue;
        }
        if options && arg.starts_with("--") {
            match arg {
                "--quiet" | "--silent" | "--regexp-extended" | "--separate" | "--unbuffered"
                | "--posix" | "--sandbox" | "--follow-symlinks" => {}
                "--expression" => {
                    scripts.push(args.get(i).ok_or("missing sed expression")?.as_str());
                    i += 1;
                }
                "--in-place" => result.in_place = true,
                _ if arg.starts_with("--expression=") => scripts.push(&arg[13..]),
                _ if arg.starts_with("--in-place=") => {
                    validate_backup_suffix(&arg[11..])?;
                    result.in_place = true;
                }
                _ => return Err("unsupported sed option or external script"),
            }
            continue;
        }
        if options && arg.starts_with('-') && arg.len() > 1 {
            for (offset, flag) in arg[1..].char_indices() {
                match flag {
                    'n' | 'E' | 'r' | 's' | 'u' => {}
                    'e' => {
                        let rest = &arg[offset + 2..];
                        if rest.is_empty() {
                            scripts.push(args.get(i).ok_or("missing sed expression")?.as_str());
                            i += 1;
                        } else {
                            scripts.push(rest);
                        }
                        break;
                    }
                    'i' | 'I' => {
                        result.in_place = true;
                        validate_backup_suffix(&arg[offset + 2..])?;
                        // BSD uses a separate empty suffix for no backup. GNU
                        // treats it as an empty script; neither can hide a file.
                        if arg[offset + 2..].is_empty() && args.get(i).is_some_and(String::is_empty)
                        {
                            i += 1;
                        }
                        break;
                    }
                    _ => return Err("unsupported sed option or external script"),
                }
            }
            continue;
        }
        operands.push(arg);
    }
    // Option parsing must finish first: any -e, including one after the first
    // operand, makes ALL operands input files rather than a positional script.
    if scripts.is_empty() && !operands.is_empty() {
        scripts.push(operands.remove(0));
    }
    result.files = operands.into_iter().map(str::to_string).collect();
    if scripts.iter().any(|script| !safe_script(script)) {
        return Err("sed script cannot be proven free of extra file I/O or execution");
    }
    Ok(result)
}

fn validate_backup_suffix(suffix: &str) -> Result<(), &'static str> {
    if suffix
        .chars()
        .any(|ch| ch.is_control() || matches!(ch, '/' | '\\' | '*' | '$' | '`'))
    {
        return Err("sed backup suffix may redirect writes outside the input directory");
    }
    Ok(())
}

fn delimited(chars: &[char], i: &mut usize, delimiter: char) -> bool {
    while let Some(&ch) = chars.get(*i) {
        *i += 1;
        if ch == '\\' {
            if *i >= chars.len() {
                return false;
            }
            *i += 1;
        } else if ch == delimiter {
            return true;
        } else if ch == '\n' || ch == '\r' {
            return false;
        }
    }
    false
}

fn address(chars: &[char], i: &mut usize) -> bool {
    match chars.get(*i) {
        Some('$') => *i += 1,
        Some('/') => {
            *i += 1;
            if !delimited(chars, i, '/') {
                return false;
            }
        }
        Some(ch) if ch.is_ascii_digit() => {
            while chars.get(*i).is_some_and(char::is_ascii_digit) {
                *i += 1;
            }
        }
        _ => return false,
    }
    true
}

fn safe_script(script: &str) -> bool {
    let chars: Vec<char> = script.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        while chars
            .get(i)
            .is_some_and(|ch| matches!(ch, ' ' | '\t' | '\n' | ';'))
        {
            i += 1;
        }
        if i == chars.len() {
            break;
        }
        if matches!(chars.get(i), Some('$' | '/')) || chars[i].is_ascii_digit() {
            if !address(&chars, &mut i) {
                return false;
            }
            if chars.get(i) == Some(&',') {
                i += 1;
                if !address(&chars, &mut i) {
                    return false;
                }
            }
            while chars.get(i).is_some_and(|ch| matches!(ch, ' ' | '\t')) {
                i += 1;
            }
            if chars.get(i) == Some(&'!') {
                i += 1;
            }
        }
        let Some(&command) = chars.get(i) else {
            return false;
        };
        i += 1;
        match command {
            's' | 'y' => {
                let Some(&delimiter) = chars.get(i) else {
                    return false;
                };
                if delimiter.is_alphanumeric() || delimiter.is_whitespace() || delimiter == '\\' {
                    return false;
                }
                i += 1;
                if !delimited(&chars, &mut i, delimiter) || !delimited(&chars, &mut i, delimiter) {
                    return false;
                }
                if command == 's' {
                    while chars.get(i).is_some_and(|ch| {
                        ch.is_ascii_digit() || matches!(ch, 'g' | 'p' | 'i' | 'I' | 'm' | 'M')
                    }) {
                        i += 1;
                    }
                }
            }
            'p' | 'P' | 'd' | 'D' | 'n' | 'N' | 'h' | 'H' | 'g' | 'G' | 'x' | '=' | 'z' => {}
            _ => return false,
        }
        while chars.get(i).is_some_and(|ch| matches!(ch, ' ' | '\t')) {
            i += 1;
        }
        if i < chars.len() && !matches!(chars[i], ';' | '\n') {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn ordinary_transformations_and_portable_in_place_forms_are_modeled() {
        for args in [
            vec!["-i.bak", "s/before/after/g", "fixture.txt"],
            vec!["-i", "", "s/before/after/", "fixture.txt"],
            vec!["--in-place=.bak", "-e", "s|before|after|", "fixture.txt"],
            vec!["-ni.bak", "1,5s/before/after/p", "fixture.txt"],
        ] {
            let parsed = parse(&argv(&args)).unwrap();
            assert!(parsed.in_place);
            assert_eq!(parsed.files, vec!["fixture.txt"]);
        }
        for script in ["1,5p", "/before/d", "s/a\\/b/c/;p", "s/a/w e/g"] {
            assert!(safe_script(script), "{script}");
        }
    }

    #[test]
    fn external_script_and_secondary_side_effects_fail_closed() {
        for args in [
            vec!["-f", "script.sed", "fixture.txt"],
            vec!["w extra.txt", "fixture.txt"],
            vec!["s/before/after/w extra.txt", "fixture.txt"],
            vec!["e printf harmless", "fixture.txt"],
            vec!["s/before/after/e", "fixture.txt"],
            vec!["-i../backup", "s/before/after/", "fixture.txt"],
            vec!["--unknown", "s/before/after/", "fixture.txt"],
        ] {
            assert!(parse(&argv(&args)).is_err(), "{args:?}");
        }
    }
}
