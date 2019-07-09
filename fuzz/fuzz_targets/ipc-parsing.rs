#![no_main]
#[macro_use]
extern crate libfuzzer_sys;

use titun::ipc::parse::parse_command_io;
use futures::executor::block_on;

fuzz_target!(|data: &[u8]| {
    let _ = block_on(parse_command_io(data));
});
