use std::process::Command;

const MANIFEST: &str = r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
        </requestedPrivileges>
    </security>
</trustInfo>
</assembly>
"#;

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
        .unwrap_or_else(|_| "".to_string());
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);

    if std::env::var_os("CARGO_CFG_UNIX").is_some() {
        cc::Build::new()
            .file("src/wireguard/tun_unix.c")
            .compile("tun_unix");
    } else if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        if std::env::var("CARGO_CFG_TARGET_ENV") == Ok("msvc".into()) {
            println!("cargo:rerun-if-env-changed=TESTING");
            if std::env::var_os("TESTING").is_none() {
                winres::WindowsResource::new()
                    .set_icon("src/icon.ico")
                    .set_icon_with_id("src/icon-red.ico", "2")
                    .set_manifest(MANIFEST)
                    .compile()
                    .expect("compile resource");
            }

            // Use rustc to build import library for NCI.dll.
            //
            // We do not use a def file and lib.exe because that alone won't
            // work for x86. We need `name type: undecorated` exports:
            //
            // https://qualapps.blogspot.com/2007/08/how-to-create-32-bit-import-libraries.html
            //
            // Good news is rustc also generate such exports for stdcall
            // functions. So we use rustc to build a dummy DLL and use the
            // generated lib file.
            let out_dir = std::env::var("OUT_DIR").unwrap();
            let rustc_status = Command::new(std::env::var_os("RUSTC").unwrap())
                .arg("--crate-name=nci")
                .arg("--crate-type=cdylib")
                .arg("--out-dir")
                .arg(&out_dir)
                .arg("--target")
                .arg(std::env::var_os("TARGET").unwrap())
                .arg("src/nci-import.rs")
                .status()
                .unwrap();
            if !rustc_status.success() {
                panic!(
                    "failed to build import lib for NCI.dll, rustc exit status: {}",
                    rustc_status
                );
            }
            // The lib file is named `nci.dll.lib`.
            println!("cargo:rustc-link-lib=static=nci.dll");
            println!("cargo:rustc-link-search=native={}", out_dir);
        } else {
            // We only use the windows-gnu target for cross checking. So no need
            // to worry about linking.
        }
    }
}
