#![no_main]

use libfuzzer_sys::fuzz_target;
use passless_core::agent::protocol::{RequestFrame, SeqpacketCodec, Validate};

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = SeqpacketCodec::decode::<RequestFrame>(data) else {
        return;
    };

    let validation = frame.validate();

    if validation.is_ok() {
        let encoded = SeqpacketCodec::encode(&frame)
            .expect("a decoded, validated request frame must remain encodable");
        let decoded = SeqpacketCodec::decode::<RequestFrame>(&encoded)
            .expect("an encoded request frame must decode again");
        assert_eq!(decoded, frame);
    }
});
