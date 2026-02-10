//! Concurrent access tests for storage adapters
//!
//! Tests that storage adapters handle concurrent access safely.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_storage_concurrent_read() {
        use std::thread;
        use std::time::Duration;

        let storage_dir = std::env::temp_dir().join("test_concurrent_read");
        std::fs::create_dir_all(&storage_dir).expect("Failed to create test directory");

        let mut storage = passless_storage::LocalStorageAdapter::new(storage_dir.clone())
            .expect("Failed to create storage adapter");

        // Create multiple credentials
        for i in 0..10 {
            let mut storage2 = passless_storage::LocalStorageAdapter::new(storage_dir.clone())
                .expect("Failed to create storage adapter");

            let dummy_credential = create_dummy_credential(&storage_dir);
            storage2
                .write(dummy_credential)
                .expect("Failed to write credential");
        }

        // Read all credentials concurrently
        let mut handles = Vec::new();
        for i in 0..10 {
            let storage_dir_clone = storage_dir.clone();
            handles.push(thread::spawn(move || {
                let mut storage = passless_storage::LocalStorageAdapter::new(storage_dir_clone)
                    .expect("Failed to create storage adapter");

                // Try to read all credentials
                let filter = passless_storage::CredentialFilter::None;
                let result = storage.read_first(filter);

                // Should succeed or return error (not panic)
                if result.is_ok() {
                    while let Ok(cred) = storage.read_next() {
                        // Just read, don't do anything with it
                    }
                }
            }));
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap_or_else(|e| {
                panic!("Thread panicked: {:?}", e);
            });
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn test_local_storage_concurrent_write() {
        use std::thread;
        use std::time::Duration;

        let storage_dir = std::env::temp_dir().join("test_concurrent_write");
        std::fs::create_dir_all(&storage_dir).expect("Failed to create test directory");

        let mut storage = passless_storage::LocalStorageAdapter::new(storage_dir.clone())
            .expect("Failed to create storage adapter");

        // Create multiple writers
        let mut handles = Vec::new();
        for i in 0..10 {
            let storage_dir_clone = storage_dir.clone();
            handles.push(thread::spawn(move || {
                let mut storage = passless_storage::LocalStorageAdapter::new(storage_dir_clone)
                    .expect("Failed to create storage adapter");

                let dummy_credential = create_dummy_credential(&storage_dir);
                storage
                    .write(dummy_credential)
                    .expect("Failed to write credential");
            }));
        }

        // Wait for all writers to complete
        for handle in handles {
            handle.join().unwrap_or_else(|e| {
                panic!("Thread panicked: {:?}", e);
            });
        }

        // Verify all credentials were written
        let storage = passless_storage::LocalStorageAdapter::new(storage_dir)
            .expect("Failed to create storage adapter");

        let count = storage.count_credentials();
        assert_eq!(count, 10, "Should have written 10 credentials");

        // Cleanup
        let _ = std::fs::remove_dir_all(storage_dir);
    }

    #[test]
    fn test_local_storage_concurrent_mixed() {
        use std::thread;

        let storage_dir = std::env::temp_dir().join("test_concurrent_mixed");
        std::fs::create_dir_all(&storage_dir).expect("Failed to create test directory");

        // Create writers and readers
        let mut handles = Vec::new();

        // 5 writers
        for i in 0..5 {
            let storage_dir_clone = storage_dir.clone();
            handles.push(thread::spawn(move || {
                let mut storage = passless_storage::LocalStorageAdapter::new(storage_dir_clone)
                    .expect("Failed to create storage adapter");

                let dummy_credential = create_dummy_credential(&storage_dir);
                storage
                    .write(dummy_credential)
                    .expect("Failed to write credential");
            }));
        }

        // 5 readers
        for i in 0..5 {
            let storage_dir_clone = storage_dir.clone();
            handles.push(thread::spawn(move || {
                let mut storage = passless_storage::LocalStorageAdapter::new(storage_dir_clone)
                    .expect("Failed to create storage adapter");

                let filter = passless_storage::CredentialFilter::None;
                let result = storage.read_first(filter);

                if result.is_ok() {
                    while let Ok(cred) = storage.read_next() {
                        // Just read, don't do anything with it
                    }
                }
            }));
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap_or_else(|e| {
                panic!("Thread panicked: {:?}", e);
            });
        }

        // Verify all credentials were written
        let storage = passless_storage::LocalStorageAdapter::new(storage_dir)
            .expect("Failed to create storage adapter");

        let count = storage.count_credentials();
        assert_eq!(count, 5, "Should have written 5 credentials");

        // Cleanup
        let _ = std::fs::remove_dir_all(storage_dir);
    }

    // Helper function to create a dummy credential for testing
    fn create_dummy_credential(storage_dir: &std::path::Path) -> soft_fido2::CredentialRef {
        use soft_fido2::CredentialRef;

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
