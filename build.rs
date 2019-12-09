use std::io::Write;
use std::path::Path;
use std::process::Command;

fn msvc_link_dll(name: &str, methods: &[&str]) {
    let output_dir = std::env::var("OUT_DIR").unwrap();
    let def_path = Path::new(&output_dir).join(name).with_extension("def");
    let lib_path = Path::new(&output_dir).join(name).with_extension("lib");

    let mut def_file = std::fs::File::create(&def_path).expect("create def_file");
    writeln!(def_file, "LIBRARY {}.dll", name).expect("def_file write");
    writeln!(def_file, "EXPORTS").expect("def_file write");
    for method in methods {
        writeln!(def_file, "{}", method).expect("def_file write");
    }
    def_file.flush().expect("def_file flush");
    drop(def_file);

    let mut lib_exe =
        cc::windows_registry::find(&std::env::var("TARGET").unwrap(), "lib.exe").unwrap();
    lib_exe
        .arg(format!("/def:{}", def_path.display()))
        .arg(format!("/out:{}", lib_path.display()))
        .status()
        .unwrap();

    println!("cargo:rustc-link-lib=static={}", name);
    println!("cargo:rustc-link-search=native={}", output_dir);
}

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
    } else if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        if std::env::var("CARGO_CFG_TARGET_ENV") == Ok("msvc".into()) {
            msvc_link_dll("NCI", &["NciGetConnectionName", "NciSetConnectionName"]);
        } else {
            // We only use the windows-gnu target for cross checking. So no need
            // to worry about linking.
        }
    }
}
