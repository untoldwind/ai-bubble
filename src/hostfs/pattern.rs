//! A small, self-contained glob matcher for hostfs mirror patterns.
//!
//! Patterns are absolute paths whose components may contain wildcards:
//!
//! - `*` matches any run of characters **within one path component** (it
//!   never crosses `/`, like in a shell),
//! - `?` matches a single character,
//! - `[...]` is a character class (ranges via `-`, negated by a leading
//!   `!` or `^`; to match a literal `]` put it first),
//! - `**` as a **whole component** matches across directory boundaries,
//!   including zero directories (`/usr/share/**/*.rs` matches
//!   `/usr/share/x.rs`),
//! - `**` **inside** a longer component (`a**b`) degrades to `*` (like in
//!   the shell) — it never spans directories; spell `dir/**/part` when
//!   spanning is intended,
//! - matching is **case-sensitive** and operates on UTF-8 text: a path
//!   component that is not valid UTF-8 can never match, so every
//!   pattern-derived decision about it fails closed (not visible, not
//!   writable — see [`Pattern::has_non_utf8_component`]).
//!
//! Everything else matches literally. A single compiled `Pattern` serves
//! both full matches (does this path name the pattern?) and the partial
//! walks the mirror needs for its ancestor/prefix checks — there is no
//! separate whole-path representation.

use std::path::{Component, Path};

/// Why a pattern could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError {
    pub pattern: String,
    pub reason: String,
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid pattern {:?}: {}", self.pattern, self.reason)
    }
}

impl std::error::Error for PatternError {}

/// One element of a single path component's pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Literal(char),
    /// `?`
    Any,
    /// `*`
    Star,
    /// `[...]`
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ClassItem {
    Single(char),
    Range(char, char),
}

/// One path component of a compiled pattern.
#[derive(Clone, Debug)]
enum Comp {
    /// `**`: spans directories.
    DoubleStar,
    /// A wildcard-carrying component; `**` embedded in a longer component
    /// (e.g. `a**b`) degrades to `*`, like in the shell.
    Chars(Vec<Token>),
}

/// A compiled mirror pattern: a sequence of path components, each either
/// literal-with-wildcards or a `**`.
#[derive(Clone, Debug)]
pub struct Pattern {
    comps: Vec<Comp>,
}

impl Pattern {
    /// Compile a pattern. Errors are reported with the original text so
    /// the caller can point at the offending spec entry.
    pub fn new(pattern: &str) -> Result<Pattern, PatternError> {
        let mut comps = Vec::new();
        for part in pattern.split('/').filter(|c| !c.is_empty()) {
            if part == "**" {
                comps.push(Comp::DoubleStar);
            } else {
                comps.push(Comp::Chars(tokenize(part).map_err(|reason| {
                    PatternError {
                        pattern: pattern.to_string(),
                        reason,
                    }
                })?));
            }
        }
        Ok(Pattern { comps })
    }

    /// The path's components as strings, or `None` when any of them is not
    /// valid UTF-8 (such components can never match a pattern).
    fn path_comps(path: &Path) -> Option<Vec<&str>> {
        path.components()
            .filter_map(|c| match c {
                Component::Normal(name) => Some(name.to_str()),
                _ => None,
            })
            .collect()
    }

    /// Whether any *normal* component of the path is not valid UTF-8.
    /// Such components can never match a pattern, so every decision a
    /// pattern could inform must **fail closed**: the path is treated as
    /// not matching (lookups/listings) and as not writable (writes) —
    /// otherwise a non-UTF-8 spelling of a hidden name would bypass the
    /// spec entirely. Used by the mirror's write checks.
    pub fn has_non_utf8_component(path: &Path) -> bool {
        path.components().any(|c| {
            matches!(c, Component::Normal(name) if name.to_str().is_none())
        })
    }

    /// Whether the pattern names the path exactly (a `**` may span any
    /// number of directories). `*` never crosses `/`, like in a shell.
    pub fn matches(&self, path: &Path) -> bool {
        let Some(comps) = Self::path_comps(path) else {
            return false;
        };
        self.match_from(0, &comps)
    }

    fn match_from(&self, pi: usize, comps: &[&str]) -> bool {
        match self.comps.get(pi) {
            None => comps.is_empty(),
            Some(Comp::DoubleStar) => {
                // Consume zero components (the `**` ends here) or one
                // (it spans another directory level).
                self.match_from(pi + 1, comps)
                    || (!comps.is_empty() && self.match_from(pi, &comps[1..]))
            }
            Some(Comp::Chars(tokens)) => {
                let Some(name) = comps.first() else {
                    return false;
                };
                let chars: Vec<char> = name.chars().collect();
                match_component(tokens, &chars) && self.match_from(pi + 1, &comps[1..])
            }
        }
    }

    /// Walk the pattern alongside a (partial) path, telling the caller how
    /// the two relate. Used for the mirror's ancestor/prefix checks; exact
    /// matches are answered by [`Pattern::matches`].
    pub fn walk(&self, path: &Path) -> Walk {
        let mut pi = 0;
        for c in path.components() {
            let Component::Normal(name) = c else {
                continue;
            };
            if pi >= self.comps.len() {
                // The pattern ran out: it names a strict ancestor. This is
                // checked *before* the UTF-8 check below so that a
                // non-UTF-8 tail still reports "ancestor": a mirrored
                // directory is a recursive mirror, and hiding its
                // non-UTF-8-named children from the ancestor check would
                // make lookup fail while readdir keeps listing them (see
                // `dir_entries`, which fails closed for such names).
                return Walk::Ancestor;
            }
            // Non-UTF-8 components can never match a pattern.
            let Some(name) = name.to_str() else {
                return Walk::Fail;
            };
            match &self.comps[pi] {
                Comp::DoubleStar => {
                    // The pattern covers this directory and everything
                    // below it.
                    return Walk::StarStar;
                }
                Comp::Chars(tokens) => {
                    let chars: Vec<char> = name.chars().collect();
                    if !match_component(tokens, &chars) {
                        return Walk::Fail;
                    }
                }
            }
            pi += 1;
        }
        if pi == self.comps.len() {
            Walk::Exact
        } else if matches!(self.comps[pi], Comp::DoubleStar) {
            // A trailing `**` covers this directory and everything below
            // it, including zero levels in between.
            Walk::StarStar
        } else {
            Walk::CouldReach
        }
    }

    /// Walk the pattern alongside a (partial) path like [`Pattern::walk`],
    /// also returning how many path components were matched before the
    /// walk concluded (`None` on `Walk::Fail`): the full path component
    /// count for `Exact` and `CouldReach`, the pattern's component count
    /// for `Ancestor`, and the number of components before the `**` for
    /// `StarStar`. Used to compare *how deep* two patterns reach into a
    /// directory subtree (the rename restriction, see `HostFs`).
    pub fn walk_depth(&self, path: &Path) -> Option<(Walk, usize)> {
        let mut pi = 0;
        let mut matched = 0usize;
        for c in path.components() {
            let Component::Normal(name) = c else {
                continue;
            };
            if pi >= self.comps.len() {
                // The pattern ran out: it names a strict ancestor (see
                // `walk` for the non-UTF-8 ordering rationale).
                return Some((Walk::Ancestor, self.comps.len()));
            }
            // Non-UTF-8 components can never match a pattern.
            let name = name.to_str()?;
            match &self.comps[pi] {
                Comp::DoubleStar => {
                    // The pattern covers this directory and everything
                    // below it; only the components before the `**` were
                    // matched literally.
                    return Some((Walk::StarStar, pi));
                }
                Comp::Chars(tokens) => {
                    let chars: Vec<char> = name.chars().collect();
                    if !match_component(tokens, &chars) {
                        return None;
                    }
                }
            }
            pi += 1;
            matched += 1;
        }
        if pi == self.comps.len() {
            Some((Walk::Exact, matched))
        } else if matches!(self.comps[pi], Comp::DoubleStar) {
            Some((Walk::StarStar, pi))
        } else {
            Some((Walk::CouldReach, matched))
        }
    }

    /// If walking `path` leaves the pattern with a next component that is
    /// purely literal (no wildcards), return that component. Used to
    /// enumerate the virtual directory entries of `empty` paths below a
    /// directory the host does not (or only partially) provide.
    pub fn next_literal(&self, path: &Path) -> Option<String> {
        let mut pi = 0;
        for c in path.components() {
            let Component::Normal(name) = c else {
                continue;
            };
            let name = name.to_str()?;
            if pi >= self.comps.len() {
                return None;
            }
            match &self.comps[pi] {
                Comp::DoubleStar => return None,
                Comp::Chars(tokens) => {
                    let chars: Vec<char> = name.chars().collect();
                    if !match_component(tokens, &chars) {
                        return None;
                    }
                }
            }
            pi += 1;
        }
        match self.comps.get(pi) {
            Some(Comp::Chars(tokens)) if tokens.iter().all(|t| matches!(t, Token::Literal(_))) => {
                Some(
                    tokens
                        .iter()
                        .map(|t| match t {
                            Token::Literal(c) => c.to_string(),
                            _ => unreachable!("checked above"),
                        })
                        .collect(),
                )
            }
            _ => None,
        }
    }
}

/// Walk result of comparing a pattern's components against a path's
/// components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Walk {
    /// The pattern names the path exactly (all pattern components
    /// consumed when the path ran out).
    Exact,
    /// A `**` component was reached: the pattern covers this directory
    /// and everything below it.
    StarStar,
    /// The pattern was fully consumed before the path was: it names a
    /// strict ancestor of the path.
    Ancestor,
    /// The path was fully consumed while the pattern still had components
    /// left: the path could be an ancestor of something the pattern
    /// matches deeper down.
    CouldReach,
    /// No match.
    Fail,
}

/// Parse one component into tokens. Returns the error reason on failure.
fn tokenize(part: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = part.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                // Collapse runs of stars; `**` inside a longer component
                // behaves like a single `*` (see the module docs).
                if tokens.last() != Some(&Token::Star) {
                    tokens.push(Token::Star);
                }
            }
            '?' => tokens.push(Token::Any),
            '[' => {
                let (negated, items) = parse_class(&mut chars)?;
                tokens.push(Token::Class { negated, items });
            }
            c => tokens.push(Token::Literal(c)),
        }
    }
    Ok(tokens)
}

/// Parse a character class; `chars` sits just after the opening `[`.
fn parse_class(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<(bool, Vec<ClassItem>), String> {
    let mut negated = false;
    if matches!(chars.peek(), Some('!') | Some('^')) {
        negated = true;
        chars.next();
    }
    let mut items = Vec::new();
    // A `]` directly after `[` or `[!` is a literal member.
    if chars.peek() == Some(&']') {
        chars.next();
        items.push(ClassItem::Single(']'));
    }
    loop {
        let Some(c) = chars.next() else {
            return Err("unclosed character class".to_string());
        };
        if c == ']' {
            return Ok((negated, items));
        }
        // A range needs a next char and a `-` after it.
        if c != '-' && chars.peek() == Some(&'-') && chars.clone().nth(1).is_some_and(|n| n != ']')
        {
            chars.next(); // the '-'
            let end = chars.next().expect("checked above");
            if end < c {
                return Err(format!("invalid character range {c}-{end}"));
            }
            items.push(ClassItem::Range(c, end));
        } else {
            items.push(ClassItem::Single(c));
        }
    }
}

/// Match one path component against its tokens. `Star` needs the classic
/// backtracking walk; filenames are short, so the quadratic behavior is
/// irrelevant.
fn match_component(tokens: &[Token], text: &[char]) -> bool {
    match tokens.first() {
        None => text.is_empty(),
        Some(Token::Literal(c)) => {
            text.first() == Some(c) && match_component(&tokens[1..], &text[1..])
        }
        Some(Token::Any) => !text.is_empty() && match_component(&tokens[1..], &text[1..]),
        Some(Token::Class { negated, items }) => {
            !text.is_empty()
                && class_matches(items, text[0]) != *negated
                && match_component(&tokens[1..], &text[1..])
        }
        Some(Token::Star) => {
            // Try every split point, longest first for typical
            // "prefix*.ext" usage.
            (0..=text.len())
                .rev()
                .any(|k| match_component(&tokens[1..], &text[k..]))
        }
    }
}

fn class_matches(items: &[ClassItem], c: char) -> bool {
    items.iter().any(|item| match item {
        ClassItem::Single(s) => *s == c,
        ClassItem::Range(a, b) => *a <= c && c <= *b,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pattern: &str, path: &str) -> bool {
        Pattern::new(pattern).unwrap().matches(Path::new(path))
    }

    #[test]
    fn literal_paths_match_exactly() {
        assert!(m("/etc/passwd", "/etc/passwd"));
        assert!(!m("/etc/passwd", "/etc/passwd.bak"));
        assert!(!m("/etc/passwd", "/etc"));
        // Empty patterns match nothing but the (empty) root path form.
        assert!(Pattern::new("").unwrap().matches(Path::new("/")));
        assert!(!Pattern::new("").unwrap().matches(Path::new("/etc")));
    }

    #[test]
    fn star_stays_within_one_component() {
        assert!(m("/etc/*.conf", "/etc/foo.conf"));
        assert!(!m("/etc/*.conf", "/etc/a/b.conf"));
        assert!(!m("/etc/*.conf", "/etc/conf"));
        // Leading dots are matched like any character.
        assert!(m("/etc/*", "/etc/.hidden"));
        // A leading slash is optional in what the bridge passes.
        assert!(m("/etc/*", "etc/foo.conf"));
        // `**` embedded in a longer component degrades to `*`.
        assert!(m("/etc/a**b", "/etc/aXXb"));
        assert!(!m("/etc/a**b", "/etc/a/x/b"));
    }

    #[test]
    fn question_mark_matches_one_character() {
        assert!(m("/etc/f?o", "/etc/foo"));
        assert!(!m("/etc/f?o", "/etc/fo"));
        assert!(!m("/etc/f?o", "/etc/fooo"));
    }

    #[test]
    fn double_star_spans_directories() {
        assert!(m("/usr/share/**/*.rs", "/usr/share/doc/x/y.rs"));
        assert!(m("/usr/share/**/*.rs", "/usr/share/x.rs"));
        assert!(!m("/usr/share/**/*.rs", "/usr/share/doc/x/y.c"));
        assert!(!m("/usr/share/**/*.rs", "/usr/x.rs"));
        // `**` alone covers everything below.
        assert!(m("/usr/share/**", "/usr/share/doc/x/y.rs"));
        assert!(m("/usr/share/**", "/usr/share/doc"));
        assert!(m("/usr/share/**", "/usr/share"));
    }

    #[test]
    fn character_classes() {
        assert!(m("/etc/[abc].conf", "/etc/a.conf"));
        assert!(!m("/etc/[abc].conf", "/etc/d.conf"));
        assert!(m("/etc/[a-c].conf", "/etc/b.conf"));
        assert!(!m("/etc/[a-c].conf", "/etc/d.conf"));
        assert!(m("/etc/[!a-c].conf", "/etc/d.conf"));
        assert!(!m("/etc/[!a-c].conf", "/etc/b.conf"));
        // A leading `]` is a literal member.
        assert!(m("/etc/[]x].conf", "/etc/].conf"));
        assert!(m("/etc/[]x].conf", "/etc/x.conf"));
        // A `-` at the edges is literal.
        assert!(m("/etc/[-a].conf", "/etc/-.conf"));
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        assert!(Pattern::new("/etc/[a").is_err());
        assert!(Pattern::new("/etc/[z-a]").is_err());
        let e = Pattern::new("/etc/[a").unwrap_err();
        assert!(e.to_string().contains("/etc/[a"));
    }

    #[test]
    fn walk_reports_the_relationship() {
        let p = Pattern::new("/etc/*.conf").unwrap();
        assert_eq!(p.walk(Path::new("/etc/foo.conf")), Walk::Exact);
        assert_eq!(p.walk(Path::new("/etc")), Walk::CouldReach);
        assert_eq!(p.walk(Path::new("/")), Walk::CouldReach);
        assert_eq!(p.walk(Path::new("/etc/foo.conf/x")), Walk::Ancestor);
        assert_eq!(p.walk(Path::new("/var")), Walk::Fail);

        let p = Pattern::new("/usr/share/**").unwrap();
        assert_eq!(p.walk(Path::new("/usr/share/doc")), Walk::StarStar);
        assert_eq!(p.walk(Path::new("/usr/share")), Walk::StarStar);

        let p = Pattern::new("/etc/passwd").unwrap();
        assert_eq!(p.walk(Path::new("/etc/passwd/x")), Walk::Ancestor);
        assert_eq!(p.walk(Path::new("/etc/passwd")), Walk::Exact);
        assert_eq!(p.walk(Path::new("/etc")), Walk::CouldReach);
    }

    #[test]
    fn non_utf8_paths_never_match() {
        use std::os::unix::ffi::OsStrExt;
        let weird = Path::new("/etc").join(std::ffi::OsStr::from_bytes(b"ba\xffd"));
        let p = Pattern::new("/etc/*").unwrap();
        assert!(!p.matches(&weird));
        assert_eq!(p.walk(&weird), Walk::Fail);
        // But when the pattern runs out before the path, the path names a
        // strict ancestor even with a non-UTF-8 tail: an exactly-named
        // directory is a recursive mirror, so the ancestor check must hold
        // (readdir fails closed for such names separately).
        let deep = Path::new("/etc").join(std::ffi::OsStr::from_bytes(b"\xff")).join("x");
        assert_eq!(Pattern::new("/etc").unwrap().walk(&deep), Walk::Ancestor);
    }
}
