#![no_main]
#[macro_use]
extern crate libfuzzer_sys;

use futures::executor::block_on;
use titun::ipc::parse::parse_command_io;

fuzz_target!(|data: &[u8]| {
    let _ = block_on(parse_command_io(data));
});
