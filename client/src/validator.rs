use std::path::Path;

/// Error type for validation failures.
#[derive(Debug)]
pub struct ValidationError {
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Validation error: {}", self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Trait for pluggable file validators.
/// Validators are registered by file extension and invoked on the first
/// segment of each file during download.
pub trait FileValidator: Send + Sync {
    /// Returns the file extensions this validator handles (without the dot).
    fn file_extensions(&self) -> &[&str];

    /// Validate the first segment of a file.
    /// This is called with the decrypted first segment data in memory.
    fn validate_first_segment(&self, data: &[u8]) -> Result<(), ValidationError>;
}

/// Validates safetensors files by parsing the JSON header.
/// Safetensors format: 8 bytes (u64 LE) = header length N, then N bytes of JSON.
pub struct SafetensorsValidator;

impl FileValidator for SafetensorsValidator {
    fn file_extensions(&self) -> &[&str] {
        &["safetensors"]
    }

    fn validate_first_segment(&self, data: &[u8]) -> Result<(), ValidationError> {
        if data.len() < 8 {
            return Err(ValidationError {
                message: "file too small to be a valid safetensors file".into(),
            });
        }

        // Read the header length (u64 little-endian)
        let header_len = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;

        // Sanity check: header should not be absurdly large
        if header_len > 100_000_000 {
            return Err(ValidationError {
                message: format!("safetensors header length {} is unreasonably large", header_len),
            });
        }

        // Check we have at least the header bytes
        if data.len() < 8 + header_len {
            // This might be OK if the file is split across segments — but the header
            // should fit in the first 64MB segment for any reasonable model.
            return Err(ValidationError {
                message: "safetensors header extends beyond first segment".into(),
            });
        }

        // Parse the JSON header
        let header_json = &data[8..8 + header_len];
        let parsed: serde_json::Value = serde_json::from_slice(header_json).map_err(|e| {
            ValidationError {
                message: format!("safetensors header is not valid JSON: {}", e),
            }
        })?;

        // Verify it's a JSON object
        if !parsed.is_object() {
            return Err(ValidationError {
                message: "safetensors header is not a JSON object".into(),
            });
        }

        // Check for required "__metadata__" or tensor entries (basic sanity)
        let obj = parsed.as_object().unwrap();
        if obj.is_empty() {
            return Err(ValidationError {
                message: "safetensors header is empty".into(),
            });
        }

        Ok(())
    }
}

/// Generic validator that accepts all data (passthrough).
pub struct GenericValidator;

impl FileValidator for GenericValidator {
    fn file_extensions(&self) -> &[&str] {
        &[] // matches nothing by extension; used as fallback
    }

    fn validate_first_segment(&self, _data: &[u8]) -> Result<(), ValidationError> {
        Ok(())
    }
}

/// Registry of validators, looked up by file extension.
pub struct ValidatorRegistry {
    validators: Vec<Box<dyn FileValidator>>,
    fallback: Box<dyn FileValidator>,
}

impl ValidatorRegistry {
    pub fn new() -> Self {
        ValidatorRegistry {
            validators: vec![Box::new(SafetensorsValidator)],
            fallback: Box::new(GenericValidator),
        }
    }

    /// Find the appropriate validator for a file path.
    pub fn validator_for(&self, path: &str) -> &dyn FileValidator {
        let ext = Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        for v in &self.validators {
            if v.file_extensions().iter().any(|e| *e == ext) {
                return v.as_ref();
            }
        }

        self.fallback.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safetensors_validator_valid() {
        let header = serde_json::json!({
            "__metadata__": {"format": "pt"},
            "weight1": {"dtype": "F32", "shape": [10, 10], "data_offsets": [0, 400]}
        });
        let header_bytes = serde_json::to_vec(&header).unwrap();
        let mut data = vec![0u8; 8];
        let len = header_bytes.len() as u64;
        data[..8].copy_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&header_bytes);

        let validator = SafetensorsValidator;
        assert!(validator.validate_first_segment(&data).is_ok());
    }

    #[test]
    fn test_safetensors_validator_invalid_json() {
        let mut data = vec![0u8; 8];
        let len = 5u64;
        data[..8].copy_from_slice(&len.to_le_bytes());
        data.extend_from_slice(b"NOT{JSON");

        let validator = SafetensorsValidator;
        assert!(validator.validate_first_segment(&data).is_err());
    }

    #[test]
    fn test_safetensors_validator_too_small() {
        let data = b"tiny";
        let validator = SafetensorsValidator;
        assert!(validator.validate_first_segment(data).is_err());
    }

    #[test]
    fn test_generic_validator_accepts_all() {
        let validator = GenericValidator;
        assert!(validator.validate_first_segment(b"anything").is_ok());
        assert!(validator.validate_first_segment(b"").is_ok());
    }

    #[test]
    fn test_registry_lookup() {
        let registry = ValidatorRegistry::new();
        let v = registry.validator_for("model.safetensors");
        // Should be SafetensorsValidator
        assert_eq!(v.file_extensions(), &["safetensors"]);

        let v = registry.validator_for("config.json");
        // Should be GenericValidator (fallback)
        let exts: &[&str] = v.file_extensions();
        assert!(exts.is_empty());
    }
}
