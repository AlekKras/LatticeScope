//! LatticeScope — defensive auditing framework for post-quantum cryptography
//! implementations.
//!
//! Two modules:
//!   * `tvla`         — microarchitectural timing-leakage detection (dudect/TVLA)
//!   * `fuzz-lattice` — structure-aware algebraic/NTT fuzzing of deserialisers
//!
//! Point it only at implementations you are authorised to test. It loads a
//! local shared object you supply, times or fuzzes specific exported symbols,
//! and reports findings; it performs no key recovery and has no remote surface.

mod fuzz;
mod mutators;
#[allow(dead_code)] // decompress/unpack_bits and the KYBER_*/DILITHIUM_* constants exist as round-trip pairs for compress/pack_bits, exercised by packing's own tests, with no other in-tree caller
mod packing;
mod profiles;
mod stats;
mod sys;
mod tvla;
mod ui;

use std::path::Path;
use std::process::Command;

// ---------------------------------------------------------------------------
// tiny argument parser
// ---------------------------------------------------------------------------

struct Args {
    positional: Vec<String>,
    flags: Vec<(String, String)>,
    switches: Vec<String>,
}

impl Args {
    fn parse(raw: &[String]) -> Args {
        let mut a = Args { positional: Vec::new(), flags: Vec::new(), switches: Vec::new() };
        let mut i = 0;
        while i < raw.len() {
            let t = &raw[i];
            if let Some(name) = t.strip_prefix("--") {
                // A value follows unless the next token is another flag or absent.
                if i + 1 < raw.len() && !raw[i + 1].starts_with("--") {
                    a.flags.push((name.to_string(), raw[i + 1].clone()));
                    i += 2;
                } else {
                    a.switches.push(name.to_string());
                    i += 1;
                }
            } else {
                a.positional.push(t.clone());
                i += 1;
            }
        }
        a
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }
    fn str_or<'a>(&'a self, name: &str, default: &'a str) -> &'a str {
        self.get(name).unwrap_or(default)
    }
    fn u64_or(&self, name: &str, default: u64) -> u64 {
        self.get(name).and_then(|v| v.parse().ok()).unwrap_or(default)
    }
    fn usize_opt(&self, name: &str) -> Option<usize> {
        self.get(name).and_then(|v| v.parse().ok())
    }
    fn u32_opt(&self, name: &str) -> Option<u32> {
        self.get(name).and_then(|v| v.parse().ok())
    }
    fn i32_or(&self, name: &str, default: i32) -> i32 {
        self.get(name).and_then(|v| v.parse().ok()).unwrap_or(default)
    }
    fn f64_or(&self, name: &str, default: f64) -> f64 {
        self.get(name).and_then(|v| v.parse().ok()).unwrap_or(default)
    }
}

fn usage() -> String {
    format!(
        "LatticeScope — PQC implementation auditor\n\n\
         USAGE:\n  latticescope <command> [options]\n\n\
         COMMANDS:\n\
         \x20 tvla           TVLA timing-leakage detection on a target symbol\n\
         \x20 fuzz-lattice   structure-aware fuzzing of a deserialiser/decapsulator\n\
         \x20 replay         re-run one saved crash and confirm the signal matches\n\
         \x20 demo           run both modules against the bundled mock target\n\
         \x20 list           list known parameter profiles\n\n\
         COMMON:\n\
         \x20 --target <path.so>   shared object to audit (required for tvla/fuzz)\n\
         \x20 --profile <name>     parameter profile (default kyber768); see `list`\n\
         \x20 --symbol <name>      override the symbol to exercise\n\
         \x20 --core <n>           pin to logical CPU n (default -1 = unpinned)\n\
         \x20 --seed <n>           RNG seed (default 1)\n\
         \x20 --refresh <hz>       live redraw rate (default 12)\n\
         \x20 --json [path]        write a one-line JSON summary (stderr if no path)\n\n\
         tvla: --op dec|enc|verify  --iters {}  --batch 2000  --warmup 20000  --reservoir 100000\n\
         fuzz-lattice: --surface deserialize|dec|compressed  --iters 100000  --batch 200  --timeout 1.0\n\
         \x20             --crash-dir crashes  --in-len <n>  --out-len <n>  --field-bits <n>\n\
         \x20             --fork-server (persistent server; default is one fork per exec)\n\
         replay: --crash <path.json>  [--profile kyber768]  [--timeout 1.0]\n\
         demo: --quick  --only both|tvla|fuzz\n\n\
         Audit only targets you are authorised to test.\n",
        200_000
    )
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

fn resolve_profile(a: &Args) -> Result<&'static profiles::Profile, String> {
    let name = a.str_or("profile", "kyber768");
    profiles::get(name).ok_or_else(|| {
        format!("unknown profile '{name}'. known: {}", profiles::names().join(", "))
    })
}

/// Write the `--json` summary to the given path, or to stderr for a bare
/// `--json` switch with no path. No-op if `--json` wasn't passed at all.
fn emit_json(a: &Args, summary: &str) {
    if let Some(path) = a.get("json") {
        if let Err(e) = std::fs::write(path, format!("{summary}\n")) {
            eprintln!("warning: could not write --json summary to {path}: {e}");
        }
    } else if a.has("json") {
        eprintln!("{summary}");
    }
}

fn cmd_tvla(a: &Args) -> Result<i32, String> {
    let target = a.get("target").ok_or("tvla requires --target <path.so>")?;
    let profile = resolve_profile(a)?;
    let op = tvla::Op::parse(a.str_or("op", "dec"))
        .ok_or("--op must be dec|enc|verify")?;
    let core = a.i32_or("core", -1);
    let seed = a.u64_or("seed", 1);
    let reservoir = a.usize_opt("reservoir").unwrap_or(100_000);
    let iters = a.u64_or("iters", 200_000);
    let batch = a.u64_or("batch", 2000);
    let warmup = a.u64_or("warmup", 20_000);
    let refresh = a.f64_or("refresh", 12.0);

    let mut engine = tvla::TvlaEngine::new(target, profile, op, a.get("symbol"), core, reservoir, seed)?;
    let st = tvla::run(&mut engine, iters, batch, warmup, refresh);
    let exit = if st.verdict == tvla::Verdict::Leak { 2 } else { 0 };
    emit_json(a, &tvla::summary_json(&st, exit));
    Ok(exit)
}

fn cmd_fuzz(a: &Args) -> Result<i32, String> {
    let target = a.get("target").ok_or("fuzz-lattice requires --target <path.so>")?;
    let profile = resolve_profile(a)?;
    let surface = fuzz::Surface::parse(a.str_or("surface", "deserialize"))
        .ok_or("--surface must be deserialize|dec|compressed")?;
    let core = a.i32_or("core", -1);
    let seed = a.u64_or("seed", 1);
    let iters = a.u64_or("iters", 100_000);
    let batch = a.u64_or("batch", 200);
    let refresh = a.f64_or("refresh", 12.0);
    let crash_dir = a.str_or("crash-dir", "crashes");
    let timeout = a.f64_or("timeout", 1.0);

    let mut engine = fuzz::FuzzEngine::new(
        target,
        profile,
        surface,
        a.get("symbol"),
        core,
        seed,
        crash_dir,
        timeout,
        a.usize_opt("in-len"),
        a.usize_opt("out-len"),
        a.u32_opt("field-bits"),
        a.has("fork-server"),
    )?;
    let st = fuzz::run(&mut engine, iters, batch, refresh);
    let exit = if st.crashes > 0 { 2 } else { 0 };
    emit_json(a, &fuzz::summary_json(&st, &engine.signal_counts(), exit));
    Ok(exit)
}

fn cmd_replay(a: &Args) -> Result<i32, String> {
    let target = a.get("target").ok_or("replay requires --target <path.so>")?;
    let crash_path = a.get("crash").ok_or("replay requires --crash <path.json>")?;

    let json = std::fs::read_to_string(crash_path)
        .map_err(|e| format!("could not read {crash_path}: {e}"))?;
    let signame = fuzz::json_str_field(&json, "signame")
        .ok_or("crash record missing 'signame'")?;
    let func = fuzz::json_str_field(&json, "func").ok_or("crash record missing 'func'")?;
    let kind = fuzz::json_str_field(&json, "kind").ok_or("crash record missing 'kind'")?;
    let n = fuzz::json_int_field(&json, "n").unwrap_or(256).max(1) as usize;
    let seed = fuzz::json_int_field(&json, "seed").unwrap_or(0) as u64;

    let surface = fuzz::Surface::from_kind_str(&kind)
        .ok_or_else(|| format!("unknown surface kind '{kind}' in crash record"))?;

    let bin_path = Path::new(crash_path).with_extension("bin");
    let payload = std::fs::read(&bin_path)
        .map_err(|e| format!("could not read {}: {e}", bin_path.display()))?;

    // Only Surface::Dec needs key material at all, and the crash record
    // doesn't carry the original run's --seed (only the per-exec seed
    // derived from it), so this sk is deterministic but not necessarily
    // byte-identical to the original run's — see README's replay section.
    let profile = resolve_profile(a)?;
    let sk_len = if surface == fuzz::Surface::Dec { profile.sk_len.max(1) } else { 0 };
    let mut sk_rng = mutators::Rng::new(seed ^ 0x5151_2626_ABCD_1234);
    let sk: Vec<u8> = (0..sk_len).map(|_| (sk_rng.next_u64() & 0xFF) as u8).collect();

    let timeout = a.f64_or("timeout", 1.0);
    let outcome = fuzz::replay_once(target, &func, surface, &payload, n, &sk, timeout)?;

    let observed = match outcome {
        sys::Outcome::Signaled(sig) => fuzz::signal_name(sig).to_string(),
        sys::Outcome::TimedOut => "TIMEOUT".to_string(),
        sys::Outcome::Exited(code) => format!("EXITED({code})"),
        sys::Outcome::ForkFailed => "FORK_FAILED".to_string(),
    };

    println!("crash record : {crash_path}");
    println!("payload      : {}", bin_path.display());
    println!("symbol       : {func}");
    println!("recorded     : {signame}");
    println!("observed     : {observed}");

    if observed == signame {
        println!("MATCH — replay reproduced the recorded crash.");
        Ok(0)
    } else {
        println!("MISMATCH — replay did not reproduce the recorded signal.");
        Ok(2)
    }
}

fn ensure_mock() -> Result<String, String> {
    let baked = env!("LS_MOCK_SO");
    if Path::new(baked).exists() {
        return Ok(baked.to_string());
    }
    // Rebuild from the bundled source if the baked path is stale.
    let src = env!("LS_MOCK_SRC");
    if !Path::new(src).exists() {
        return Err("bundled mock source not found; run from the source tree".into());
    }
    let tmp = std::env::temp_dir().join("libmock_pqc_ls.so");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let status = Command::new(&cc)
        .args(["-O3", "-fPIC", "-shared", "-o"])
        .arg(&tmp)
        .arg(src)
        .status()
        .map_err(|e| format!("could not invoke C compiler '{cc}': {e}"))?;
    if !status.success() {
        return Err("mock target build failed (a C compiler is required for `demo`)".into());
    }
    Ok(tmp.to_string_lossy().into_owned())
}

fn cmd_demo(a: &Args) -> Result<i32, String> {
    let mock = ensure_mock()?;
    let quick = a.has("quick");
    let only = a.str_or("only", "both");
    let mut exit = 0;

    if only == "both" || only == "fuzz" {
        println!("── demo: fuzzing the planted-bug deserialiser (poly_frombytes_vuln) ──");
        let profile = profiles::get("mock").unwrap();
        let mut fe = fuzz::FuzzEngine::new(
            &mock,
            profile,
            fuzz::Surface::Deserialize,
            Some("poly_frombytes_vuln"),
            -1,
            1,
            "crashes",
            1.0,
            None,
            None,
            None,
            a.has("fork-server"),
        )?;
        let iters = if quick { 4_000 } else { 40_000 };
        let st = fuzz::run(&mut fe, iters, 200, 12.0);
        if st.crashes > 0 {
            exit = 2;
        }
        println!();

        println!("── demo: fuzzing the planted-bug compressed-ciphertext decompressor (decompress_ct_vuln) ──");
        let mut ce = fuzz::FuzzEngine::new(
            &mock,
            profile,
            fuzz::Surface::Compressed,
            Some("decompress_ct_vuln"),
            -1,
            1,
            "crashes",
            1.0,
            None,
            None,
            None,
            a.has("fork-server"),
        )?;
        let st = fuzz::run(&mut ce, iters, 200, 12.0);
        if st.crashes > 0 {
            exit = 2;
        }
        println!();
    }

    if only == "both" || only == "tvla" {
        println!("── demo: TVLA on the leaky decapsulation (crypto_kem_dec) ──");
        let profile = profiles::get("mock").unwrap();
        let mut te = tvla::TvlaEngine::new(&mock, profile, tvla::Op::Dec, Some("crypto_kem_dec"), -1, 100_000, 1)?;
        let iters = if quick { 40_000 } else { 200_000 };
        let st = tvla::run(&mut te, iters, 2000, if quick { 4000 } else { 20_000 }, 12.0);
        if st.verdict == tvla::Verdict::Leak {
            exit = 2;
        }
        println!(
            "\nnegative control: re-run with `--symbol crypto_kem_dec_ct` — the constant-time\n\
             variant should NOT be flagged."
        );
    }

    Ok(exit)
}

fn cmd_list() -> Result<i32, String> {
    println!("{:<12} {:<6} {:>5} {:>10} {:>6}  symbols", "profile", "fam", "n", "q", "bits");
    for p in profiles::PROFILES {
        let fam = match p.family {
            profiles::Family::Kem => "kem",
            profiles::Family::Sign => "sign",
        };
        println!(
            "{:<12} {:<6} {:>5} {:>10} {:>6}  {}",
            p.name,
            fam,
            p.n,
            p.q,
            p.poly_bits,
            [p.sym_dec, p.sym_enc, p.sym_verify]
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(0)
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() || raw[0] == "-h" || raw[0] == "--help" || raw[0] == "help" {
        print!("{}", usage());
        std::process::exit(if raw.is_empty() { 1 } else { 0 });
    }

    let cmd = raw[0].clone();
    let a = Args::parse(&raw[1..]);

    let result = match cmd.as_str() {
        "tvla" => cmd_tvla(&a),
        "fuzz-lattice" | "fuzz" => cmd_fuzz(&a),
        "replay" => cmd_replay(&a),
        "demo" => cmd_demo(&a),
        "list" | "list-profiles" => cmd_list(),
        other => {
            eprintln!("unknown command '{other}'\n");
            print!("{}", usage());
            std::process::exit(1);
        }
    };

    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}