#![no_main]
#[macro_use] extern crate libfuzzer_sys;

use titun::crypto::blake2s::blake2s;

fuzz_target!(|data: &[u8]| {
    blake2s(32, &[], data);
});
