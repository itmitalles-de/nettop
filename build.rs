use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=bpf/lifecycle.bpf.c");
    println!("cargo:rerun-if-env-changed=NWTOP_BPF_CLANG");
    if env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86",
        Ok("aarch64") => "arm64",
        other => panic!("nwtop ebpf supports only Linux x86_64/aarch64 targets, got {other:?}"),
    };
    assert_eq!(
        env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("linux"),
        "nwtop ebpf requires Linux"
    );
    assert_eq!(
        env::var("CARGO_CFG_TARGET_ENDIAN").as_deref(),
        Ok("little"),
        "nwtop ebpf currently requires little-endian x86_64/aarch64"
    );
    let output =
        PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR")).join("lifecycle.bpf.o");
    let compiler = env::var_os("NWTOP_BPF_CLANG").unwrap_or_else(|| "clang".into());
    let mut command = Command::new(&compiler);
    command.args([
        "-target",
        "bpfel",
        "-O2",
        "-g",
        "-Wall",
        "-Werror",
        "-c",
        "bpf/lifecycle.bpf.c",
    ]);
    command.arg(format!("-D__TARGET_ARCH_{arch}"));
    // Debian/Ubuntu keep asm/types.h in the build host's multiarch include dir.
    // These fixed-width Linux UAPI types do not depend on the monitored ABI.
    let host = env::var("HOST").unwrap_or_default();
    let includes = if host.starts_with("x86_64-") {
        "/usr/include/x86_64-linux-gnu"
    } else if host.starts_with("aarch64-") {
        "/usr/include/aarch64-linux-gnu"
    } else {
        "/usr/include"
    };
    command.arg("-I").arg(includes).arg("-o").arg(&output);
    let result = command.output().unwrap_or_else(|error| {
        panic!("optional ebpf build needs clang with BPF support and libbpf development headers: {error}")
    });
    assert!(
        result.status.success(),
        "optional ebpf compilation failed; install clang and libbpf-dev (or equivalent):\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
