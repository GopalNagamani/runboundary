//! Windows-specific lexical checks for future handle-relative filesystem access.
//!
//! This module has no Unix imports or external dependencies, so the same tests
//! can run on Windows with rustc before the rest of the CLI is ported. It does
//! not open files or implement a sandbox. Reparse points, short-name aliases,
//! file identity, ACLs and races still require Windows handle-based checks.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelativePath(String);

impl RelativePath {
    /// Slash-separated spelling, preserving filename case and Unicode.
    /// This is not a case-insensitive file identity or a canonical host path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    Empty,
    TooLong,
    RootOrNamespace,
    TraversalOrEmptyComponent,
    InvalidCharacter,
    TrailingDotOrSpace,
    ReservedDevice,
    ShortNameSyntax,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "Windows project path must not be empty",
            Self::TooLong => "Windows project path or component exceeds the supported length",
            Self::RootOrNamespace => {
                "Windows project path must be relative without a drive or namespace prefix"
            }
            Self::TraversalOrEmptyComponent => {
                "Windows project paths must not contain traversal or empty components"
            }
            Self::InvalidCharacter => {
                "Windows project path contains a reserved character or control character"
            }
            Self::TrailingDotOrSpace => {
                "Windows project components must not end with a dot or space"
            }
            Self::ReservedDevice => "Windows project path names a reserved device",
            Self::ShortNameSyntax => {
                "tilde spellings are unsupported until short-name identity checks are implemented"
            }
        })
    }
}

impl std::error::Error for PathError {}

/// Validate an untrusted, workspace-relative Windows path before any lookup.
/// Both separators have Windows semantics even when tested from a Unix host.
pub fn validate_relative(input: &str) -> Result<RelativePath, PathError> {
    if input.is_empty() {
        return Err(PathError::Empty);
    }
    if input.encode_utf16().count() > 32_760 {
        return Err(PathError::TooLong);
    }
    if input.starts_with(['/', '\\']) || input.contains(':') {
        // Includes UNC, rooted, drive-relative, extended-length, NT/device
        // namespaces and alternate data streams. No automatic normalization.
        return Err(PathError::RootOrNamespace);
    }
    let normalized = input.replace('\\', "/");
    for part in normalized.split('/') {
        if part.is_empty() || matches!(part, "." | "..") {
            return Err(PathError::TraversalOrEmptyComponent);
        }
        if part.encode_utf16().count() > 255 {
            return Err(PathError::TooLong);
        }
        if part
            .chars()
            .any(|c| c.is_control() || "<>\"|?*".contains(c))
        {
            return Err(PathError::InvalidCharacter);
        }
        if part.ends_with(['.', ' ']) {
            return Err(PathError::TrailingDotOrSpace);
        }
        // Device names remain reserved with extensions, e.g. NUL.txt. Trim
        // spaces before the extension conservatively rather than depending on
        // different Win32/NT parsing behavior.
        let stem = part.split('.').next().unwrap_or("").trim_end_matches(' ');
        let upper = stem.to_ascii_uppercase();
        let numbered_device = ["COM", "LPT"].iter().any(|prefix| {
            upper.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        });
        if matches!(
            upper.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || numbered_device
        {
            return Err(PathError::ReservedDevice);
        }
        if part.contains('~') {
            // A tilde is not proof of an 8.3 alias. Refuse such spellings in
            // this first phase instead of claiming lexical alias resolution.
            return Err(PathError::ShortNameSyntax);
        }
    }
    Ok(RelativePath(normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_paths_preserve_case_spaces_and_unicode() {
        for input in [
            "src/main.rs",
            "View Controllers/Score.swift",
            "资源/页面.swift",
            ".env.example",
        ] {
            assert_eq!(validate_relative(input).unwrap().as_str(), input);
        }
        assert_eq!(
            validate_relative(r"src\nested\main.rs").unwrap().as_str(),
            "src/nested/main.rs"
        );
        assert_eq!(
            validate_relative(r"src\nested/main.rs").unwrap().as_str(),
            "src/nested/main.rs"
        );
        // Protected-file exclusion belongs to the policy matcher, not this
        // syntactic validator. A valid name does not imply permission to copy.
        assert!(validate_relative(".env").is_ok());
    }

    #[test]
    fn drive_unc_nt_and_device_namespaces_are_rejected() {
        for input in [
            r"C:\project\file",
            "C:file",
            r"\file",
            "/file",
            r"\\server\share\file",
            r"\\?\C:\file",
            r"\\.\PhysicalDrive0",
            r"\??\C:\file",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\file",
        ] {
            assert_eq!(validate_relative(input), Err(PathError::RootOrNamespace));
        }
    }

    #[test]
    fn traversal_and_ambiguous_separators_are_rejected() {
        for input in [
            ".",
            "..",
            "../file",
            r"src\..\file",
            "src/./file",
            "src//file",
            "src/",
            r"src\\file",
        ] {
            assert!(
                validate_relative(input).is_err(),
                "accepted traversal/ambiguous spelling"
            );
        }
        assert_eq!(validate_relative(""), Err(PathError::Empty));
    }

    #[test]
    fn alternate_streams_and_attributes_are_rejected() {
        for input in [
            "source.txt:secret",
            "source.txt::$DATA",
            "directory:$INDEX_ALLOCATION",
            r"src\file:$DATA",
        ] {
            assert_eq!(validate_relative(input), Err(PathError::RootOrNamespace));
        }
    }

    #[test]
    fn reserved_devices_are_rejected_with_extensions_and_case_variants() {
        for name in [
            "CON",
            "con.txt",
            "PrN.log",
            "AUX",
            "nul.tar.gz",
            "COM1",
            "com9.txt",
            "LPT1",
            "lpt9.log",
            "COM¹.txt",
            "COM²",
            "LPT³.txt",
            "NUL .txt",
            "CONIN$",
            "CONOUT$",
        ] {
            assert_eq!(
                validate_relative(&format!("src/{name}")),
                Err(PathError::ReservedDevice)
            );
        }
        for name in ["console.txt", "auxiliary.rs", "COM10.txt", "LPT0.txt"] {
            assert!(validate_relative(name).is_ok());
        }
    }

    #[test]
    fn trailing_dot_space_wildcards_and_controls_are_rejected() {
        for input in [
            "file.",
            "file ",
            "src./file",
            "src /file",
            "file?.txt",
            "file*.txt",
            "a|b",
            "a<b",
            "a>b",
            "a\"b",
            "a\0b",
            "a\nb",
            "a\u{1f}b",
        ] {
            assert!(validate_relative(input).is_err());
        }
    }

    #[test]
    fn short_name_spellings_fail_closed_without_claiming_alias_resolution() {
        for input in ["SECRET~1.TXT", "src/PRODUC~1.KEY", "ordinary~name"] {
            assert_eq!(validate_relative(input), Err(PathError::ShortNameSyntax));
        }
    }

    #[test]
    fn lengths_count_utf16_units_and_enforce_bounded_paths() {
        assert!(validate_relative(&"x".repeat(255)).is_ok());
        assert_eq!(validate_relative(&"x".repeat(256)), Err(PathError::TooLong));
        assert!(validate_relative(&"🦀".repeat(127)).is_ok());
        assert_eq!(
            validate_relative(&"🦀".repeat(128)),
            Err(PathError::TooLong)
        );
        let oversized = std::iter::repeat_n("x".repeat(255), 130)
            .collect::<Vec<_>>()
            .join("/");
        assert_eq!(validate_relative(&oversized), Err(PathError::TooLong));
    }
}
