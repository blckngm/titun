use std::process::Command;

fn main() {
    let git_hash = Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()
        .map(|output| {
            String::from_utf8(output.stdout)
                .unwrap()
                .chars()
                .take(10)
                .collect()
        })
        .unwrap_or("".to_string());
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);

    if std::env::var_os("CARGO_CFG_UNIX").is_some() {
        cc::Build::new()
            .file("src/wireguard/tun_unix.c")
            .compile("tun_unix");
    }
}
