//! Rendering untrusted text where a person decides.
//!
//! An approval prompt, a ledger listing and a hook reason all restate text an
//! agent chose. Shown raw, a carriage return or escape sequence rewrites the
//! line a person is reading, and a bidirectional override reorders it, without
//! changing what would run.

/// Replace every character that can move, hide or reorder displayed text with
/// a visible `\u{…}` escape. Printable text, including non-ASCII, is kept.
pub fn display_safe(text: &str) -> String {
    let mut safe = String::with_capacity(text.len());
    for ch in text.chars() {
        // Any white space but the ASCII space: a no-break or ideographic
        // space inside a name reads as the gap between two names.
        let blank = ch.is_whitespace() && ch != ' ';
        if ch.is_control() || blank || is_invisible_format(ch) {
            safe.extend(ch.escape_unicode());
        } else {
            safe.push(ch);
        }
    }
    safe
}

/// Characters with no glyph of their own, or a blank one, that are neither
/// control characters nor white space: soft hyphen, combining grapheme
/// joiner, bidirectional marks, embeddings, overrides and isolates,
/// zero-width characters, Hangul and Khmer fillers, Mongolian and general
/// variation selectors, the blank Braille pattern, shorthand and musical
/// format controls, interlinear annotation marks, and tag characters.
fn is_invisible_format(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn characters_that_rewrite_a_line_become_visible_escapes() {
        assert_eq!(display_safe("a\u{1b}[2Kb"), "a\\u{1b}[2Kb");
        assert_eq!(display_safe("a\rb\nc\td"), "a\\u{d}b\\u{a}c\\u{9}d");
        assert_eq!(display_safe("main\u{202e}niam"), "main\\u{202e}niam");
        assert_eq!(
            display_safe("ma\u{200b}in\u{feff}"),
            "ma\\u{200b}in\\u{feff}"
        );
        assert_eq!(display_safe("x\u{2066}y\u{2069}"), "x\\u{2066}y\\u{2069}");
        assert_eq!(
            display_safe("a\u{0}b\u{7f}\u{9b}"),
            "a\\u{0}b\\u{7f}\\u{9b}"
        );
    }

    /// Characters with no glyph, or a blank one, that are not control
    /// characters: fillers, variation selectors, non-ASCII spaces. In a name
    /// they are invisible differences; a space among them reads as two words.
    #[test]
    fn invisible_and_blank_characters_become_visible_escapes() {
        for ch in [
            '\u{00A0}',
            '\u{034F}',
            '\u{115F}',
            '\u{1160}',
            '\u{1680}',
            '\u{17B4}',
            '\u{17B5}',
            '\u{180B}',
            '\u{180F}',
            '\u{2003}',
            '\u{205F}',
            '\u{2800}',
            '\u{3000}',
            '\u{3164}',
            '\u{FE00}',
            '\u{FE0F}',
            '\u{FFA0}',
            '\u{1BCA0}',
            '\u{1D173}',
            '\u{1D17A}',
            '\u{E0100}',
            '\u{E01EF}',
        ] {
            let shown = display_safe(&format!("origin{ch}"));
            assert_eq!(
                shown,
                format!("origin\\u{{{:x}}}", ch as u32),
                "U+{:04X} must be shown as an escape",
                ch as u32
            );
        }
    }

    #[test]
    fn printable_text_is_unchanged() {
        for text in [
            "origin",
            "feature/safe-name_1",
            "功能/登录",
            "café — ok",
            "",
        ] {
            assert_eq!(display_safe(text), text);
        }
    }
}
