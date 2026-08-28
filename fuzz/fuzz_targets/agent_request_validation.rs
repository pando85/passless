#![no_main]

use std::fmt::Debug;

use libfuzzer_sys::fuzz_target;
use passless_core::agent::protocol::{
    AdminRequest, PrincipalRequest, RegisterCredentialRequest, Validate,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

fn exercise<T>(data: &[u8])
where
    T: DeserializeOwned + Serialize + Validate + PartialEq + Debug,
{
    let Ok(value) = serde_json::from_slice::<T>(data) else {
        return;
    };

    let validation = value.validate();

    if validation.is_ok() {
        let encoded = serde_json::to_vec(&value)
            .expect("a decoded, validated request must remain serializable");
        let decoded = serde_json::from_slice::<T>(&encoded)
            .expect("a serialized request must decode again");
        assert_eq!(decoded, value);
    }
}

fuzz_target!(|data: &[u8]| {
    exercise::<AdminRequest>(data);
    exercise::<PrincipalRequest>(data);
    exercise::<RegisterCredentialRequest>(data);
});
