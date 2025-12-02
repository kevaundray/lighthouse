//! Panic-safe verification wrapper
//!
//! This module provides a wrapper function that catches panics from verifier operations
//! and converts them to `Ok(false)` so that verification failures don't crash the client.

use super::VerificationResult;
use std::panic::{catch_unwind, AssertUnwindSafe};
use tracing::error;

/// Safely calls a verifier function and catches any panics, returning false instead
///
/// This wrapper ensures that if a verifier panics for any reason, the panic is caught
/// and logged, and the function returns `Ok(false)` instead of crashing the client.
pub fn safe_verify<F>(verify_fn: F) -> VerificationResult
where
    F: FnOnce() -> VerificationResult,
{
    match catch_unwind(AssertUnwindSafe(verify_fn)) {
        Ok(result) => result,
        Err(panic_info) => {
            let panic_msg = if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "Unknown panic occurred during verification".to_string()
            };
            error!(panic_message = %panic_msg, "Verifier panicked, returning false");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_verify_with_panic() {
        // Test that panics are caught and converted to Ok(false)
        let result = safe_verify(|| {
            panic!("Test panic in verifier");
        });

        assert!(result.is_ok(), "safe_verify should return Ok, not Err");
        assert_eq!(
            result.unwrap(),
            false,
            "safe_verify should return false when panic occurs"
        );
    }

    #[test]
    fn test_safe_verify_with_ok_result() {
        // Test that normal Ok results pass through
        let result = safe_verify(|| Ok(true));

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_safe_verify_with_err_result() {
        // Test that Err results pass through
        let result = safe_verify(|| Err("Verification failed".to_string()));

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Verification failed".to_string());
    }

    #[test]
    fn test_safe_verify_with_false_result() {
        // Test that Ok(false) results pass through
        let result = safe_verify(|| Ok(false));

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }
}
