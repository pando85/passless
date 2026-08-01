from pathlib import Path

p = Path('cmd/passless/src/storage/credential.rs')
s = p.read_text()

def replace_once(old: str, new: str, label: str) -> None:
    global s
    if old not in s:
        raise RuntimeError(f'{label} not found')
    s = s.replace(old, new, 1)

replace_once(
'''    pub discoverable: bool,

    #[serde(default)]
    pub extensions: Extensions,
''',
'''    pub discoverable: bool,

    /// Backup eligibility and current backup state.
    #[serde(default)]
    pub backup_state: soft_fido2::CredentialBackupState,

    #[serde(default)]
    pub extensions: Extensions,
''',
'storage backup_state field',
)

replace_once(
'''            created: cred.created,
            discoverable: cred.discoverable,
            extensions: Extensions {
''',
'''            created: cred.created,
            discoverable: cred.discoverable,
            backup_state: cred.backup_state,
            extensions: Extensions {
''',
'from owned credential backup state',
)

replace_once(
'''            created: *cred_ref.created,
            discoverable: *cred_ref.discoverable,
            extensions: Extensions {
''',
'''            created: *cred_ref.created,
            discoverable: *cred_ref.discoverable,
            backup_state: *cred_ref.backup_state,
            extensions: Extensions {
''',
'from credential ref backup state',
)

replace_once(
'''            created: self.created,
            discoverable: self.discoverable,
            extensions: soft_fido2::Extensions {
''',
'''            created: self.created,
            discoverable: self.discoverable,
            backup_state: self.backup_state,
            extensions: soft_fido2::Extensions {
''',
'to soft credential backup state',
)

replace_once(
'''            created: self.created,
            discoverable: self.discoverable,
            extensions: self.extensions,
''',
'''            created: self.created,
            discoverable: self.discoverable,
            backup_state: self.backup_state,
            extensions: self.extensions,
''',
'into owned backup state',
)

replace_once(
'''            created: i64,
            discoverable: bool,
            #[serde(default)]
            extensions: Extensions,
''',
'''            created: i64,
            discoverable: bool,
            #[serde(default)]
            backup_state: soft_fido2::CredentialBackupState,
            #[serde(default)]
            extensions: Extensions,
''',
'owned credential backup state field',
)

replace_once(
'''            created: owned.created,
            discoverable: owned.discoverable,
            extensions: owned.extensions,
''',
'''            created: owned.created,
            discoverable: owned.discoverable,
            backup_state: owned.backup_state,
            extensions: owned.extensions,
''',
'decoded credential backup state',
)

# Two soft_fido2::Credential literals in this module predate 0.16.0.
old_soft_literal = '''            created: 1234567890,
            discoverable: true,
            extensions: soft_fido2::Extensions {
'''
new_soft_literal = '''            created: 1234567890,
            discoverable: true,
            backup_state: soft_fido2::CredentialBackupState::NotEligible,
            extensions: soft_fido2::Extensions {
'''
count = s.count(old_soft_literal)
if count != 2:
    raise RuntimeError(f'expected 2 soft credential test literals, found {count}')
s = s.replace(old_soft_literal, new_soft_literal)

replace_once(
'''            created: 0,
            discoverable: true,
            extensions: Extensions::default(),
''',
'''            created: 0,
            discoverable: true,
            backup_state: soft_fido2::CredentialBackupState::NotEligible,
            extensions: Extensions::default(),
''',
'minimal storage credential backup state',
)

# Verify the stable storage adapter now preserves the 0.16 backup state.
replace_once(
'''        assert!(deserialized.discoverable);
    }
''',
'''        assert!(deserialized.discoverable);
        assert_eq!(
            deserialized.backup_state,
            soft_fido2::CredentialBackupState::NotEligible
        );
    }
''',
'roundtrip backup state assertion',
)

p.write_text(s)
