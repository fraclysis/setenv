fn main() {
    println!("cargo:rerun-if-changed=setenv");

    if cfg!(feature = "build-dll") {
        build_dll().unwrap();
    }
}

use std::{path::PathBuf, process::Command};

pub fn build_dll() -> Result<(), Box<dyn std::error::Error>> {
    let out = get_exe_build_location();
    let out = format!("-o {}", out.to_str().unwrap());

    let opt = format!(
        "-O{}",
        std::env::var("OPT_LEVEL").unwrap_or(String::from("0"))
    );

    let warnings = "-Wall";
    let lto = "-flto -fuse-ld=lld";
    let native_libs = ["-lUser32", "-lKernel32"].join(" ");
    let crt = format!("-llibvcruntime -llibcmt -nostdlib -Xlinker /ENTRY:seDllMainCRTStartup");

    let args = format!("lib/setenv.c -g -shared {warnings} {lto} {opt} {out} {native_libs} {crt}");

    let ok = Command::new("clang").args(args.split(' ')).output()?;

    if !ok.status.success() {
        let out = std::str::from_utf8(&ok.stdout)?;
        let err = std::str::from_utf8(&ok.stderr)?;
        panic!("{out}, {err}")
    }

    Ok(())
}

fn get_exe_build_location() -> PathBuf {
    let path = std::env::var("OUT_DIR").unwrap();
    let mut path = PathBuf::from(path);
    path.pop();
    path.pop();
    path.pop();

    let mut cargo_lock = path.clone();
    cargo_lock.push(".cargo-lock");

    if cargo_lock.exists() {
        path.push("setenv.dll");
        path
    } else {
        PathBuf::from("setenv.dll")
    }
}
