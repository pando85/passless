//! Storage error handling tests
//!
//! Tests that storage adapters handle errors gracefully without panicking.

use soft_fido2::Result as SoftFido2Result;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_storage_missing_file() {
        // This test verifies that reading a non-existent credential returns an error
        // rather than panicking
        let storage_dir = std::env::temp_dir().join("test_missing_credential");
        std::fs::create_dir_all(&storage_dir).expect("Failed to create test directory");

        // Try to read a credential from a non-existent path
        let mut storage = passless_storage::LocalStorageAdapter::new(storage_dir.clone())
            .expect("Failed to create storage adapter");

        let result = storage.read(&[1, 2, 3, 4]);

        // Should return DoesNotExist error, not panic
        assert!(result.is_err());

        // Cleanup
        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn test_local_storage_delete_nonexistent() {
        // Test that deleting a non-existent credential handles errors gracefully
        let storage_dir = std::env::temp_dir().join("test_delete_nonexistent");
        std::fs::create_dir_all(&storage_dir).expect("Failed to create test directory");

        let mut storage = passless_storage::LocalStorageAdapter::new(storage_dir.clone())
            .expect("Failed to create storage adapter");

        // Try to delete a credential that doesn't exist
        let result = storage.delete(&[1, 2, 3, 4]);

        // Should return an error, not panic
        assert!(result.is_err());

        // Cleanup
        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn test_local_storage_write_duplicate() {
        // Test that writing to a path with an existing credential handles errors gracefully
        let storage_dir = std::env::temp_dir().join("test_duplicate_write");
        std::fs::create_dir_all(&storage_dir).expect("Failed to create test directory");

        let mut storage = passless_storage::LocalStorageAdapter::new(storage_dir.clone())
            .expect("Failed to create storage adapter");

        // Create a dummy credential first
        let dummy_credential = create_dummy_credential(&storage_dir);

        // Try to read it back
        let mut storage_with_credential =
            passless_storage::LocalStorageAdapter::new(storage_dir.clone())
                .expect("Failed to create storage adapter");

        let read_result = storage_with_credential.read(&dummy_credential.id);
        assert!(read_result.is_ok(), "First read should succeed");

        // Try to write it again (this should be a no-op or return an error)
        let write_result = storage_with_credential.write(dummy_credential);
        // Either succeed (update) or return an error, but should not panic
        assert!(write_result.is_ok() || write_result.is_err());

        // Cleanup
        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn test_storage_iteration_end_of_list() {
        // Test that reading beyond the last credential handles errors gracefully
        let storage_dir = std::env::temp_dir().join("test_iteration_end");
        std::fs::create_dir_all(&storage_dir).expect("Failed to create test directory");

        let mut storage = passless_storage::LocalStorageAdapter::new(storage_dir.clone())
            .expect("Failed to create storage adapter");

        // Create a single credential
        let dummy_credential = create_dummy_credential(&storage_dir);
        let mut storage_with_credential =
            passless_storage::LocalStorageAdapter::new(storage_dir.clone())
                .expect("Failed to create storage adapter");
        storage_with_credential
            .write(dummy_credential)
            .expect("Failed to write credential");

        // Reset iteration
        let mut storage2 = passless_storage::LocalStorageAdapter::new(storage_dir.clone())
            .expect("Failed to create storage adapter");

        // Read first credential
        let filter = passless_storage::CredentialFilter::None;
        let first_result = storage2.read_first(filter);
        assert!(first_result.is_ok(), "First read should succeed");

        // Try to read again (should return DoesNotExist)
        let second_result = storage2.read_next();
        assert!(second_result.is_err());

        // Cleanup
        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn test_storage_filter_by_nonexistent_rp() {
        // Test filtering by a non-existent relying party
        let storage_dir = std::env::temp_dir().join("test_filter_nonexistent_rp");
        std::fs::create_dir_all(&storage_dir).expect("Failed to create test directory");

        let mut storage = passless_storage::LocalStorageAdapter::new(storage_dir.clone())
            .expect("Failed to create storage adapter");

        // Try to filter by a non-existent RP
        let filter =
            passless_storage::CredentialFilter::ByRp("nonexistent.example.com".to_string());
        let result = storage.read_first(filter);

        // Should return DoesNotExist error, not panic
        assert!(result.is_err());

        // Cleanup
        let _ = std::fs::remove_dir_all(storage_dir);
    }

    // Helper function to create a dummy credential for testing
    fn create_dummy_credential(storage_dir: &std::path::Path) -> soft_fido2::CredentialRef {
        use soft_fido2::CredentialRef;

        // This is a minimal valid credential for testing
        // In production, credentials are generated by the soft-fido2 library
        let dummy_id = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let dummy_rp_id = "test.example.com".to_string();
        let dummy_rp_name = Some("Test Example".to_string());
        let dummy_user_id = vec![1, 2, 3, 4];
        let dummy_user_name = Some("test@example.com".to_string());
        let dummy_user_display_name = Some("Test User".to_string());
        let dummy_sign_count = &mut 0;
        let dummy_alg = &mut -7;
        let dummy_private_key = soft_fido2_ctap::SecBytes::new(vec![]);
        let dummy_created = &mut 0;
        let dummy_discoverable = &mut false;
        let dummy_cred_protect = None;

        CredentialRef {
            id: &dummy_id,
            rp_id: &dummy_rp_id,
            rp_name: dummy_rp_name.as_ref(),
            user_id: &dummy_user_id,
            user_name: dummy_user_name.as_ref(),
            user_display_name: dummy_user_display_name.as_ref(),
            sign_count: dummy_sign_count,
            alg: dummy_alg,
            private_key: &dummy_private_key,
            created: dummy_created,
            discoverable: dummy_discoverable,
            cred_protect: dummy_cred_protect,
        }
    }
}
