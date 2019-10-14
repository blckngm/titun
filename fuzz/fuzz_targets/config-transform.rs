#![no_main]
#[macro_use]
extern crate libfuzzer_sys;

use titun::cli::transform::maybe_transform;

fuzz_target!(|data: &[u8]| {
    if let Ok(data) = String::from_utf8(data.to_vec()) {
        maybe_transform(data);
    }
});
