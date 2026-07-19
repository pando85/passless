use crate::error::UhidError;
use crate::protocol::{UHID_NAME_MAX, UHID_PHYS_MAX, UHID_UNIQ_MAX};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub name: String,
    pub phys: String,
    pub uniq: String,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
}

impl DeviceIdentity {
    pub fn new(
        name: impl Into<String>,
        phys: impl Into<String>,
        uniq: impl Into<String>,
        vendor: u32,
        product: u32,
        version: u32,
    ) -> Self {
        Self {
            name: name.into(),
            phys: phys.into(),
            uniq: uniq.into(),
            vendor,
            product,
            version,
        }
    }

    pub fn validate(&self) -> Result<(), UhidError> {
        validate_field(&self.name, "name", UHID_NAME_MAX)?;
        validate_field(&self.phys, "phys", UHID_PHYS_MAX)?;
        validate_field(&self.uniq, "uniq", UHID_UNIQ_MAX)?;
        Ok(())
    }
}

fn validate_field(value: &str, field: &'static str, max: usize) -> Result<(), UhidError> {
    if value.contains('\0') {
        return Err(UhidError::IdentityNul { field });
    }
    if value.len() > max {
        return Err(UhidError::IdentityFieldTooLong {
            field,
            len: value.len(),
            max,
        });
    }
    Ok(())
}

impl Default for DeviceIdentity {
    fn default() -> Self {
        Self {
            name: "passless-uhid-test".to_string(),
            phys: String::new(),
            uniq: String::new(),
            vendor: 0xFFFF,
            product: 0xFFFF,
            version: 0x0000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_identity_default() {
        let id = DeviceIdentity::default();
        assert_eq!(id.name, "passless-uhid-test");
        assert_eq!(id.phys, "");
        assert_eq!(id.uniq, "");
        assert_eq!(id.vendor, 0xFFFF);
        assert_eq!(id.product, 0xFFFF);
        assert_eq!(id.version, 0x0000);
    }

    #[test]
    fn test_device_identity_new() {
        let id = DeviceIdentity::new("my-dev", "my-phys", "my-uniq", 0xAA, 0xBB, 0xCC);
        assert_eq!(id.name, "my-dev");
        assert_eq!(id.phys, "my-phys");
        assert_eq!(id.uniq, "my-uniq");
        assert_eq!(id.vendor, 0xAA);
        assert_eq!(id.product, 0xBB);
        assert_eq!(id.version, 0xCC);
    }

    #[test]
    fn test_device_identity_clone_eq() {
        let a = DeviceIdentity::new("dev", "p", "u", 1, 2, 3);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_validate_ok() {
        let id = DeviceIdentity::new("test", "phys", "uniq", 1, 2, 3);
        assert!(id.validate().is_ok());
    }

    #[test]
    fn test_validate_nul_in_name() {
        let id = DeviceIdentity::new("te\0st", "phys", "uniq", 1, 2, 3);
        let err = id.validate().unwrap_err();
        assert!(matches!(err, UhidError::IdentityNul { field: "name" }));
    }

    #[test]
    fn test_validate_nul_in_phys() {
        let id = DeviceIdentity::new("test", "ph\0ys", "uniq", 1, 2, 3);
        let err = id.validate().unwrap_err();
        assert!(matches!(err, UhidError::IdentityNul { field: "phys" }));
    }

    #[test]
    fn test_validate_nul_in_uniq() {
        let id = DeviceIdentity::new("test", "phys", "un\0iq", 1, 2, 3);
        let err = id.validate().unwrap_err();
        assert!(matches!(err, UhidError::IdentityNul { field: "uniq" }));
    }

    #[test]
    fn test_validate_name_too_long() {
        let id = DeviceIdentity::new("a".repeat(129), "phys", "uniq", 1, 2, 3);
        let err = id.validate().unwrap_err();
        assert!(matches!(
            err,
            UhidError::IdentityFieldTooLong {
                field: "name",
                len: 129,
                max: 128,
            }
        ));
    }

    #[test]
    fn test_validate_phys_too_long() {
        let id = DeviceIdentity::new("test", "a".repeat(65), "uniq", 1, 2, 3);
        let err = id.validate().unwrap_err();
        assert!(matches!(
            err,
            UhidError::IdentityFieldTooLong {
                field: "phys",
                len: 65,
                max: 64,
            }
        ));
    }

    #[test]
    fn test_validate_uniq_too_long() {
        let id = DeviceIdentity::new("test", "phys", "a".repeat(65), 1, 2, 3);
        let err = id.validate().unwrap_err();
        assert!(matches!(
            err,
            UhidError::IdentityFieldTooLong {
                field: "uniq",
                len: 65,
                max: 64,
            }
        ));
    }

    #[test]
    fn test_validate_max_length_ok() {
        let id = DeviceIdentity::new(
            "a".repeat(UHID_NAME_MAX),
            "b".repeat(UHID_PHYS_MAX),
            "c".repeat(UHID_UNIQ_MAX),
            1,
            2,
            3,
        );
        assert!(id.validate().is_ok());
    }

    #[test]
    fn test_default_does_not_collide_with_production() {
        let id = DeviceIdentity::default();
        assert_ne!(id.vendor, 0x15d9);
        assert_ne!(id.product, 0x0a37);
    }
}
