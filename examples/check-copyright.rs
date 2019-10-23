// Copyright 2019 Yin Guanhao <sopium@mysterious.site>

// This file is part of TiTun.

// TiTun is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// TiTun is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with TiTun.  If not, see <https://www.gnu.org/licenses/>.

use anyhow::{bail, Context};
use std::ffi::OsStr;
use walkdir::WalkDir;

fn main() -> anyhow::Result<()> {
    let dirs = ["src", "examples", "benches"];
    let mut has_error = false;
    for entry in dirs.iter().map(|dir| WalkDir::new(dir)).flatten() {
        let entry = entry?;
        if entry.file_type().is_file() && entry.path().extension() == Some(OsStr::new("rs")) {
            let file_content = std::fs::read_to_string(entry.path())
                .with_context(|| format!("open and read {}", entry.path().display()))?;
            if !file_content.starts_with("// Copyright") {
                eprintln!(
                    "Missing copyright claim in file: {}",
                    entry.path().display()
                );
                has_error = true;
            }
        }
    }
    if has_error {
        bail!("Error occurred");
    }
    Ok(())
}
