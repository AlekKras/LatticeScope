// Build the bundled mock PQC target (a deliberately-vulnerable C library used
// only by the `demo` subcommand and the self-tests). We shell out to the system
// C compiler rather than pulling in the `cc` crate, keeping the dependency set
// at exactly one (libc).
//
// The mock stays in C on purpose: one of its planted bugs is an integer
// divide-by-zero that must raise a hardware SIGFPE, and Rust guards integer
// division, so an all-Rust mock could not demonstrate that signal.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest.join("examples").join("mock_pqc.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let so = out_dir.join("libmock_pqc.so");

    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-env-changed=CC");

    // Expose both paths to the binary: the prebuilt .so, and the source so the
    // `demo` command can rebuild it at runtime if the baked path is stale.
    println!("cargo:rustc-env=LS_MOCK_SO={}", so.display());
    println!("cargo:rustc-env=LS_MOCK_SRC={}", src.display());

    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let status = Command::new(&cc)
        .args(["-O3", "-fPIC", "-shared", "-o"])
        .arg(&so)
        .arg(&src)
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => println!(
            "cargo:warning=mock target build failed ({s}); `demo` will rebuild at runtime"
        ),
        Err(e) => println!(
            "cargo:warning=could not invoke C compiler '{cc}' ({e}); `demo` will rebuild at runtime"
        ),
    }
}