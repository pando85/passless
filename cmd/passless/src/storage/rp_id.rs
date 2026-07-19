use std::fmt;
use std::ops::Deref;
use std::path::{Component, Path};

const MAX_RP_ID_LENGTH: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidatedRpId(String);

#[derive(Debug)]
pub enum RpIdValidationError {
    Empty,
    TooLong(usize),
    ContainsNull,
    ContainsForwardSlash,
    ContainsBackslash,
    ParentDirectoryComponent,
    CurrentDirectoryComponent,
    MultiplePathComponents,
    AbsolutePath,
    HiddenFile,
}

impl fmt::Display for RpIdValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "RP ID must not be empty"),
            Self::TooLong(len) => {
                write!(
                    f,
                    "RP ID too long: {} bytes (max {})",
                    len, MAX_RP_ID_LENGTH
                )
            }
            Self::ContainsNull => write!(f, "RP ID must not contain null bytes"),
            Self::ContainsForwardSlash => {
                write!(f, "RP ID must not contain '/' path separator")
            }
            Self::ContainsBackslash => {
                write!(f, "RP ID must not contain '\\' path separator")
            }
            Self::ParentDirectoryComponent => write!(f, "RP ID must not contain '..'"),
            Self::CurrentDirectoryComponent => write!(f, "RP ID must not be or contain '.'"),
            Self::MultiplePathComponents => {
                write!(f, "RP ID must be a single path component")
            }
            Self::AbsolutePath => write!(f, "RP ID must not be an absolute path"),
            Self::HiddenFile => write!(f, "RP ID must not start with '.'"),
        }
    }
}

impl TryFrom<&str> for ValidatedRpId {
    type Error = RpIdValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let trimmed = value.trim();

        if trimmed.is_empty() {
            return Err(RpIdValidationError::Empty);
        }

        if trimmed.len() > MAX_RP_ID_LENGTH {
            return Err(RpIdValidationError::TooLong(trimmed.len()));
        }

        if trimmed.contains('\0') {
            return Err(RpIdValidationError::ContainsNull);
        }

        let path = Path::new(trimmed);
        let components: Vec<_> = path.components().collect();

        match components.as_slice() {
            [Component::Normal(_)] => {}
            [Component::CurDir] => {
                return Err(RpIdValidationError::CurrentDirectoryComponent);
            }
            [Component::ParentDir] => {
                return Err(RpIdValidationError::ParentDirectoryComponent);
            }
            _ => {
                if components.iter().any(|c| matches!(c, Component::RootDir)) {
                    return Err(RpIdValidationError::AbsolutePath);
                }
                if matches!(components.first(), Some(Component::ParentDir)) {
                    return Err(RpIdValidationError::ParentDirectoryComponent);
                }
                return Err(RpIdValidationError::MultiplePathComponents);
            }
        }

        if trimmed.contains('/') {
            return Err(RpIdValidationError::ContainsForwardSlash);
        }

        if trimmed.contains('\\') {
            return Err(RpIdValidationError::ContainsBackslash);
        }

        if trimmed.starts_with('.') {
            return Err(RpIdValidationError::HiddenFile);
        }

        Ok(Self(trimmed.to_string()))
    }
}

impl ValidatedRpId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ValidatedRpId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for ValidatedRpId {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ValidatedRpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_rp_ids() {
        assert!(ValidatedRpId::try_from("example.com").is_ok());
        assert!(ValidatedRpId::try_from("webauthn.example.org").is_ok());
        assert!(ValidatedRpId::try_from("localhost").is_ok());
        assert!(ValidatedRpId::try_from("a-b-c").is_ok());
        assert!(ValidatedRpId::try_from("my-app.example.com").is_ok());
        assert!(ValidatedRpId::try_from("xn--n1e.ru").is_ok());
    }

    #[test]
    fn test_rejects_empty() {
        let err = ValidatedRpId::try_from("").unwrap_err();
        assert!(matches!(err, RpIdValidationError::Empty));
        let err = ValidatedRpId::try_from("  ").unwrap_err();
        assert!(matches!(err, RpIdValidationError::Empty));
    }

    #[test]
    fn test_rejects_path_traversal() {
        let err = ValidatedRpId::try_from("../outside").unwrap_err();
        assert!(matches!(err, RpIdValidationError::ParentDirectoryComponent));
        let err = ValidatedRpId::try_from("a/../../outside").unwrap_err();
        assert!(matches!(err, RpIdValidationError::MultiplePathComponents));
    }

    #[test]
    fn test_rejects_absolute_paths() {
        let err = ValidatedRpId::try_from("/tmp/absolute").unwrap_err();
        assert!(matches!(err, RpIdValidationError::AbsolutePath));
    }

    #[test]
    fn test_rejects_current_dir() {
        let err = ValidatedRpId::try_from(".").unwrap_err();
        assert!(matches!(
            err,
            RpIdValidationError::CurrentDirectoryComponent
        ));
        let err = ValidatedRpId::try_from("..").unwrap_err();
        assert!(matches!(err, RpIdValidationError::ParentDirectoryComponent));
    }

    #[test]
    fn test_rejects_separators() {
        let err = ValidatedRpId::try_from("foo/bar").unwrap_err();
        assert!(matches!(err, RpIdValidationError::MultiplePathComponents));
        let err = ValidatedRpId::try_from("foo\\bar").unwrap_err();
        assert!(matches!(err, RpIdValidationError::ContainsBackslash));
    }

    #[test]
    fn test_rejects_hidden_files() {
        let err = ValidatedRpId::try_from(".hidden").unwrap_err();
        assert!(matches!(err, RpIdValidationError::HiddenFile));
    }

    #[test]
    fn test_rejects_null() {
        let err = ValidatedRpId::try_from("bad\0.com").unwrap_err();
        assert!(matches!(err, RpIdValidationError::ContainsNull));
    }

    #[test]
    fn test_rejects_overlong() {
        let long = "a".repeat(MAX_RP_ID_LENGTH + 1);
        let err = ValidatedRpId::try_from(long.as_str()).unwrap_err();
        assert!(matches!(err, RpIdValidationError::TooLong(_)));
    }

    #[test]
    fn test_accepts_max_length() {
        let long = "a".repeat(MAX_RP_ID_LENGTH);
        assert!(ValidatedRpId::try_from(long.as_str()).is_ok());
    }

    #[test]
    fn test_display_and_deref() {
        let rp = ValidatedRpId::try_from("example.com").unwrap();
        assert_eq!(rp.as_str(), "example.com");
        assert_eq!(rp.to_string(), "example.com");
        assert_eq!(*rp, "example.com".to_string());
    }

    #[test]
    fn test_equality_and_hashing() {
        let a = ValidatedRpId::try_from("example.com").unwrap();
        let b = ValidatedRpId::try_from("example.com").unwrap();
        let c = ValidatedRpId::try_from("other.com").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_security_rejects_backslash_on_unix() {
        let err = ValidatedRpId::try_from("foo\\bar").unwrap_err();
        assert!(matches!(err, RpIdValidationError::ContainsBackslash));
    }

    #[test]
    fn test_security_rejects_windows_paths() {
        let err = ValidatedRpId::try_from("C:\\outside").unwrap_err();
        assert!(matches!(err, RpIdValidationError::ContainsBackslash));
    }

    #[test]
    fn test_security_rejects_unc_paths() {
        let err = ValidatedRpId::try_from("\\\\server\\share").unwrap_err();
        assert!(matches!(err, RpIdValidationError::ContainsBackslash));
    }

    #[test]
    fn test_security_rejects_null_bytes() {
        let err = ValidatedRpId::try_from("evil\0.com").unwrap_err();
        assert!(matches!(err, RpIdValidationError::ContainsNull));
    }

    #[test]
    fn test_security_rejects_empty_after_trim() {
        let err = ValidatedRpId::try_from("   ").unwrap_err();
        assert!(matches!(err, RpIdValidationError::Empty));
    }

    #[test]
    fn test_security_rejects_overlong_rp_id() {
        let long = "a".repeat(256);
        let err = ValidatedRpId::try_from(long.as_str()).unwrap_err();
        assert!(matches!(err, RpIdValidationError::TooLong(256)));
    }

    #[test]
    fn test_security_accepts_unicode_idna() {
        assert!(ValidatedRpId::try_from("xn--n1e.ru").is_ok());
        assert!(ValidatedRpId::try_from("münchen.de").is_ok());
    }
}
