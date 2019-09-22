#![no_main]
#[macro_use]
extern crate libfuzzer_sys;

use std::convert::TryInto;
use titun::crypto::xchacha20poly1305::hchacha;

fuzz_target!(|data: &[u8]| {
    if data.len() == 48 {
        hchacha(
            data[..32].try_into().unwrap(),
            &data[32..].try_into().unwrap(),
        );
    }

    // fuzzed code goes here
});
