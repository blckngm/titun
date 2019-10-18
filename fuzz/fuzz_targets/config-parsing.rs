#![no_main]
#[macro_use]
extern crate libfuzzer_sys;

use titun::cli::Config;

fuzz_target!(|data: &[u8]| {
    if let Ok(data) = std::str::from_utf8(data) {
        let _: Result<Config<String>, _> = toml::from_str(data);
    }
});
