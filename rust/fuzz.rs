//! Module 2 — structure-aware algebraic / NTT fuzzing.
//!
//! Each execution runs in a forked child so a memory-safety or arithmetic fault
//! kills only that child; the parent detects it through the reaper's
//! fork/timeout path (see `sys::Reaper`). Coefficients and the packed payload
//! are prepared in the parent *before* the fork, so the child does exactly one
//! indirect call into the target and then exits — and so a crash is fully
//! reproducible from `(base_seed, exec_index)`.

use crate::mutators::{default_strategies, Rng, Strategy};
use crate::packing::{compress, pack_bits};
use crate::profiles::{Family, Profile};
use crate::sys::{DynLib, ForkServer, Outcome, Reaper};
use crate::ui;
use std::io::Write;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

type DeserFn = unsafe extern "C" fn(*mut u8, *const u8) -> c_int;
type KemDecFn = unsafe extern "C" fn(*mut u8, *const u8, *const u8) -> c_int;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Deserialize,
    Dec,
    /// Kyber ciphertext-shaped payload: k compressed `u` polynomials at `du`
    /// bits/coefficient followed by one compressed `v` polynomial at `dv`
    /// bits/coefficient (FIPS 203's `c1 || c2`), targeting a
    /// decompress/decapsulation symbol with the same 2-arg ABI as
    /// `Deserialize`.
    Compressed,
}

impl Surface {
    pub fn parse(s: &str) -> Option<Surface> {
        match s {
            "deserialize" => Some(Surface::Deserialize),
            "dec" => Some(Surface::Dec),
            "compressed" => Some(Surface::Compressed),
            _ => None,
        }
    }
    fn kind_str(&self) -> &'static str {
        match self {
            Surface::Deserialize => "deserialize",
            Surface::Dec => "kem_dec",
            Surface::Compressed => "compressed",
        }
    }
    /// Inverse of `kind_str`, for reconstructing a surface from a saved
    /// crash record (see `replay_once`).
    pub fn from_kind_str(s: &str) -> Option<Surface> {
        match s {
            "deserialize" => Some(Surface::Deserialize),
            "kem_dec" => Some(Surface::Dec),
            "compressed" => Some(Surface::Compressed),
            _ => None,
        }
    }
}

pub fn signal_name(sig: i32) -> &'static str {
    match sig {
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGABRT => "SIGABRT",
        libc::SIGILL => "SIGILL",
        libc::SIGKILL => "SIGKILL",
        _ => "SIG?",
    }
}

#[derive(Clone)]
pub struct CrashRecord {
    pub index: u64,
    pub timestamp: f64,
    pub signal: i32,
    pub signame: String,
    pub strategy: String,
    pub seed: u64,
    pub func: String,
    pub kind: String,
    pub in_len: usize,
    pub n: usize,
    pub payload_len: usize,
    pub payload_hex: String,
    pub coeffs: Vec<u32>,
    pub boundary_indices: Vec<usize>,
    pub timed_out: bool,
    pub path: String,
    pub note: String,
}

pub struct FuzzState {
    pub target: String,
    pub symbol: String,
    pub kind: &'static str,
    pub core: i32,
    pub execs: u64,
    pub crashes: u64,
    pub unique: usize,
    pub current_strategy: String,
    pub recent: Vec<CrashRecord>,
    pub last_crash: Option<CrashRecord>,
    pub rate: f64,
    pub elapsed: f64,
    pub timeouts: u64,
}

pub struct FuzzEngine {
    _lib: DynLib,
    fptr: *const std::os::raw::c_void,
    surface: Surface,
    symbol: String,
    target_name: String,
    core: i32,
    reaper: Reaper,
    timeout: std::time::Duration,

    strategies: Vec<Box<dyn Strategy>>,
    strat_idx: usize,
    current_strategy: String,

    n: usize,
    q: u32,
    bits: u32,
    in_len_override: Option<usize>,
    du: u32,
    dv: u32,
    k: usize, // module rank, derived from ct_len/n/du/dv; unused outside Surface::Compressed

    out: Vec<u8>,   // target output buffer (preallocated, reused)
    sk: Vec<u8>,    // fixed key material for the dec surface
    fork_server: Option<ForkServer>,

    seed_base: u64,
    crash_dir: PathBuf,
    crash_dir_ready: bool,

    execs: u64,
    crashes: u64,
    timeouts: u64,
    unique: std::collections::HashSet<(i32, String)>,
    recent: Vec<CrashRecord>,
    recent_cap: usize,
    last_crash: Option<CrashRecord>,

    t0: Instant,
    last_snap_time: Instant,
    last_snap_execs: u64,
    last_rate: f64,
}

impl FuzzEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: &str,
        profile: &Profile,
        surface: Surface,
        symbol_override: Option<&str>,
        core: i32,
        seed: u64,
        crash_dir: &str,
        timeout_s: f64,
        in_len: Option<usize>,
        out_len: Option<usize>,
        field_bits: Option<u32>,
        fork_server: bool,
    ) -> Result<FuzzEngine, String> {
        let symbol = match symbol_override {
            Some(s) => s.to_string(),
            None => match surface {
                Surface::Deserialize => "poly_frombytes".to_string(),
                Surface::Dec => {
                    if profile.sym_dec.is_empty() {
                        return Err("profile has no dec symbol; pass --symbol".into());
                    }
                    profile.sym_dec.to_string()
                }
                Surface::Compressed => {
                    if profile.du == 0 {
                        return Err(
                            "profile has no du/dv (not a KEM profile); --surface compressed needs a KEM profile"
                                .into(),
                        );
                    }
                    "decompress_ct".to_string()
                }
            },
        };

        let lib = DynLib::open(target)?;
        let fptr = lib.symbol(&symbol)?;
        let target_name = Path::new(target)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| target.to_string());

        if core >= 0 {
            crate::sys::pin_cpu(core as usize);
        }

        let strategies = default_strategies(profile.family);
        let current_strategy = strategies[0].name().to_string();
        let bits = field_bits.unwrap_or(profile.poly_bits);

        let out_default = match surface {
            Surface::Deserialize | Surface::Compressed => profile.n, // mock writes n bytes out
            Surface::Dec => profile.ss_len.max(32),
        };
        let out = vec![0u8; out_len.unwrap_or(out_default).max(1)];

        // Module rank k, solved back out of ct_len = du*k*n/8 + dv*n/8 rather
        // than stored on Profile (it's only needed to shape a `compressed`
        // payload). Signature profiles have du=dv=0 and never reach here.
        let (du, dv) = (profile.du, profile.dv);
        let k = if du > 0 {
            let c2_bytes = profile.n * dv as usize / 8;
            let c1_per_poly = (profile.n * du as usize / 8).max(1);
            (profile.ct_len - c2_bytes) / c1_per_poly
        } else {
            0
        };

        // Fixed secret key material for the dec surface (deterministic).
        let mut sk_rng = Rng::new(seed ^ 0x5151_2626_ABCD_1234);
        let sk_len = if surface == Surface::Dec { profile.sk_len.max(1) } else { 0 };
        let sk: Vec<u8> = (0..sk_len).map(|_| (sk_rng.next_u64() & 0xFF) as u8).collect();
        let timeout = std::time::Duration::from_secs_f64(timeout_s.max(0.001));

        // Payload length is fixed for the whole run (pack_bits' natural width,
        // the compressed ciphertext's ct_len, or the override), so the
        // fork-server's shared region can be sized once up front exactly like
        // a per-exec payload would be.
        let fork_server = if fork_server {
            let payload_len = if surface == Surface::Compressed {
                profile.ct_len
            } else {
                let natural_len = (profile.n * bits as usize + 7) / 8;
                in_len.unwrap_or(natural_len).max(1)
            };
            let out_ptr = out.as_ptr() as *mut u8;
            let sk_ptr = sk.as_ptr();
            Some(unsafe {
                ForkServer::spawn(payload_len, timeout, move |in_ptr: *const u8| {
                    move || match surface {
                        Surface::Deserialize | Surface::Compressed => {
                            let f: DeserFn = std::mem::transmute(fptr);
                            f(out_ptr, in_ptr);
                        }
                        Surface::Dec => {
                            let f: KemDecFn = std::mem::transmute(fptr);
                            f(out_ptr, in_ptr, sk_ptr);
                        }
                    }
                })
            }?)
        } else {
            None
        };

        Ok(FuzzEngine {
            _lib: lib,
            fptr,
            surface,
            symbol,
            target_name,
            core,
            reaper: Reaper::new(),
            timeout,
            strategies,
            strat_idx: 0,
            current_strategy,
            n: profile.n,
            q: profile.q,
            bits,
            in_len_override: in_len,
            du,
            dv,
            k,
            out,
            sk,
            fork_server,
            seed_base: seed & 0xFFFF_FFFF,
            crash_dir: PathBuf::from(crash_dir),
            crash_dir_ready: false,
            execs: 0,
            crashes: 0,
            timeouts: 0,
            unique: std::collections::HashSet::new(),
            recent: Vec::new(),
            recent_cap: 12,
            last_crash: None,
            t0: Instant::now(),
            last_snap_time: Instant::now(),
            last_snap_execs: 0,
            last_rate: 0.0,
        })
    }

    fn next_strategy(&mut self) -> usize {
        let i = self.strat_idx % self.strategies.len();
        self.strat_idx += 1;
        self.current_strategy = self.strategies[i].name().to_string();
        i
    }

    fn exec_seed(&self, idx: u64) -> u64 {
        // Fully reproducible from (seed_base, idx).
        (self
            .seed_base
            .wrapping_mul(0x9E37_79B1)
            .wrapping_add(idx.wrapping_mul(2_654_435_761)))
            & 0xFFFF_FFFF
    }

    /// Generate the raw coefficients and packed payload for one (strategy,
    /// seed) pair. Shared by `step` and `build_payload` so a replay can never
    /// diverge from what actually ran.
    ///
    /// For `Surface::Compressed`, `coeffs` is the concatenation of the *raw*
    /// (pre-compression) coefficients across the k `u`-polynomials and the
    /// one `v`-polynomial — that's what `record_crash`'s boundary-index check
    /// (against `q`/`bits`, the raw domain) still means something for; the
    /// payload itself carries the du/dv-bit *compressed* values.
    fn generate(&self, strat_i: usize, seed: u64) -> (Vec<u32>, Vec<u8>) {
        let mut rng = Rng::new(seed);
        if self.surface == Surface::Compressed {
            let mut coeffs = Vec::with_capacity(self.n * (self.k + 1));
            let mut payload = Vec::with_capacity(
                self.k * (self.n * self.du as usize / 8) + self.n * self.dv as usize / 8,
            );
            for _ in 0..self.k {
                let raw = self.strategies[strat_i].generate(&mut rng, self.n, self.q, self.bits);
                let c1: Vec<u32> = raw.iter().map(|&x| compress(x, self.du, self.q)).collect();
                payload.extend(pack_bits(&c1, self.du));
                coeffs.extend(raw);
            }
            let raw_v = self.strategies[strat_i].generate(&mut rng, self.n, self.q, self.bits);
            let c2: Vec<u32> = raw_v.iter().map(|&x| compress(x, self.dv, self.q)).collect();
            payload.extend(pack_bits(&c2, self.dv));
            coeffs.extend(raw_v);
            (coeffs, payload)
        } else {
            let coeffs = self.strategies[strat_i].generate(&mut rng, self.n, self.q, self.bits);
            let mut payload = pack_bits(&coeffs, self.bits);
            if let Some(l) = self.in_len_override {
                payload.resize(l, 0);
            }
            (coeffs, payload)
        }
    }

    #[allow(dead_code)]
    /// Build the payload for a given exec index (also used for replay/verification).
    pub fn build_payload(&self, idx: u64) -> (usize, u64, Vec<u32>, Vec<u8>) {
        // NB: strategy is chosen by round-robin on idx, so replay is exact.
        let strat_i = (idx as usize) % self.strategies.len();
        let seed = self.exec_seed(idx);
        let (coeffs, payload) = self.generate(strat_i, seed);
        (strat_i, seed, coeffs, payload)
    }

    pub fn step(&mut self, n: u64) {
        for _ in 0..n {
            let idx = self.execs;
            let strat_i = self.next_strategy();
            let seed = self.exec_seed(idx);
            let (coeffs, payload) = self.generate(strat_i, seed);

            let outcome = if let Some(fs) = &self.fork_server {
                fs.payload.write(&payload);
                fs.exec()
            } else {
                self.run_child(&payload)
            };
            self.execs += 1;

            match outcome {
                Outcome::Signaled(sig) => {
                    self.record_crash(sig, false, strat_i, seed, coeffs, payload);
                }
                Outcome::TimedOut => {
                    self.timeouts += 1;
                    // A hang is also a finding; record it as SIGKILL-tagged.
                    self.record_crash(libc::SIGKILL, true, strat_i, seed, coeffs, payload);
                }
                Outcome::Exited(_) | Outcome::ForkFailed => {}
            }
        }
    }

    fn run_child(&self, payload: &[u8]) -> Outcome {
        let out_ptr = self.out.as_ptr() as *mut u8;
        let in_ptr = payload.as_ptr();
        let sk_ptr = self.sk.as_ptr();
        let fptr = self.fptr;
        let surface = self.surface;
        unsafe {
            self.reaper.run(self.timeout, move || match surface {
                Surface::Deserialize | Surface::Compressed => {
                    let f: DeserFn = std::mem::transmute(fptr);
                    f(out_ptr, in_ptr);
                }
                Surface::Dec => {
                    let f: KemDecFn = std::mem::transmute(fptr);
                    f(out_ptr, in_ptr, sk_ptr);
                }
            })
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_crash(
        &mut self,
        sig: i32,
        timed_out: bool,
        strat_i: usize,
        seed: u64,
        coeffs: Vec<u32>,
        payload: Vec<u8>,
    ) {
        self.crashes += 1;
        let strategy = self.strategies[strat_i].name().to_string();
        let key = (sig, strategy.clone());
        let is_new = self.unique.insert(key);

        let signame = signal_name(sig).to_string();
        let field_max = if self.bits >= 32 { u32::MAX } else { (1u32 << self.bits) - 1 };
        let boundary_indices: Vec<usize> = coeffs
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c >= self.q || c == field_max)
            .map(|(i, _)| i)
            .collect();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let mut rec = CrashRecord {
            index: self.execs,
            timestamp: ts,
            signal: sig,
            signame,
            strategy,
            seed,
            func: self.symbol.clone(),
            kind: self.surface.kind_str().to_string(),
            in_len: payload.len(),
            n: self.n,
            payload_len: payload.len(),
            payload_hex: ui::hex_all(&payload),
            coeffs,
            boundary_indices,
            timed_out,
            path: String::new(),
            note: "signal observed via waitpid/WIFSIGNALED; register state is \
                   not fabricated — load the payload under a debugger or enable \
                   a core dump for register-level detail"
                .to_string(),
        };

        // Only persist the first instance of each (signal, strategy) pair.
        if is_new {
            if let Err(e) = self.write_artifacts(&mut rec, &payload) {
                eprintln!("warning: could not write crash artifact: {e}");
            }
            self.recent.insert(0, rec.clone());
            if self.recent.len() > self.recent_cap {
                self.recent.truncate(self.recent_cap);
            }
        }
        self.last_crash = Some(rec);
    }

    fn write_artifacts(&mut self, rec: &mut CrashRecord, payload: &[u8]) -> std::io::Result<()> {
        if !self.crash_dir_ready {
            std::fs::create_dir_all(&self.crash_dir)?;
            self.crash_dir_ready = true;
        }
        let stem = format!("crash_{:06}_{}", rec.index, rec.signame);
        let bin_path = self.crash_dir.join(format!("{stem}.bin"));
        std::fs::write(&bin_path, payload)?;
        let json_path = self.crash_dir.join(format!("{stem}.json"));
        rec.path = bin_path.to_string_lossy().into_owned();
        std::fs::write(&json_path, crash_to_json(rec))?;
        Ok(())
    }

    pub fn snapshot(&mut self) -> FuzzState {
        let now = Instant::now();
        let dt = now.duration_since(self.last_snap_time).as_secs_f64();
        let de = self.execs - self.last_snap_execs;
        let rate = if dt > 1e-3 && de > 0 {
            let r = de as f64 / dt;
            self.last_rate = r;
            self.last_snap_time = now;
            self.last_snap_execs = self.execs;
            r
        } else {
            self.last_rate
        };

        FuzzState {
            target: self.target_name.clone(),
            symbol: self.symbol.clone(),
            kind: self.surface.kind_str(),
            core: self.core,
            execs: self.execs,
            crashes: self.crashes,
            unique: self.unique.len(),
            current_strategy: self.current_strategy.clone(),
            recent: self.recent.clone(),
            last_crash: self.last_crash.clone(),
            rate,
            elapsed: now.duration_since(self.t0).as_secs_f64(),
            timeouts: self.timeouts,
        }
    }

    /// Count of distinct `(signal, strategy)` pairs seen, grouped by signal
    /// name, for the `--json` summary. Reads the full `unique` set (not the
    /// display-capped `recent` list), so this is exact regardless of how
    /// many distinct crash types were found.
    pub fn signal_counts(&self) -> Vec<(String, usize)> {
        let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for &(sig, _) in &self.unique {
            *counts.entry(signal_name(sig).to_string()).or_insert(0) += 1;
        }
        counts.into_iter().collect()
    }
}

// ---------------------------------------------------------------------------
// replay (crash triage)
// ---------------------------------------------------------------------------

/// Run `payload` once against `symbol` in `target` for crash-triage replay,
/// via the same `Reaper` (sigtimedwait discipline, Invariant 2) and the same
/// 2-/3-arg dispatch `run_child` uses. Standalone (not a `FuzzEngine` method)
/// because replay only needs a target/symbol/surface/payload — none of a
/// live fuzz run's strategy state.
pub fn replay_once(
    target: &str,
    symbol: &str,
    surface: Surface,
    payload: &[u8],
    out_len: usize,
    sk: &[u8],
    timeout_s: f64,
) -> Result<Outcome, String> {
    let lib = DynLib::open(target)?;
    let fptr = lib.symbol(symbol)?;
    let mut out = vec![0u8; out_len.max(1)];
    let out_ptr = out.as_mut_ptr();
    let in_ptr = payload.as_ptr();
    let sk_ptr = sk.as_ptr();
    let timeout = std::time::Duration::from_secs_f64(timeout_s.max(0.001));
    let reaper = Reaper::new();
    let outcome = unsafe {
        reaper.run(timeout, move || match surface {
            Surface::Deserialize | Surface::Compressed => {
                let f: DeserFn = std::mem::transmute(fptr);
                f(out_ptr, in_ptr);
            }
            Surface::Dec => {
                let f: KemDecFn = std::mem::transmute(fptr);
                f(out_ptr, in_ptr, sk_ptr);
            }
        })
    };
    Ok(outcome)
}

/// Minimal reader for the fixed format `crash_to_json` writes (not a general
/// JSON parser: this project's crash records are self-produced, so a couple
/// of substring scans are enough — no serde, matching the writer beside it).
pub fn json_str_field(json: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\": \"");
    let start = json.find(&pat)? + pat.len();
    let end = json[start..].find('"')? + start;
    Some(json[start..end].to_string())
}

pub fn json_int_field(json: &str, key: &str) -> Option<i64> {
    let pat = format!("\"{key}\": ");
    let start = json.find(&pat)? + pat.len();
    let end = json[start..].find(|c: char| c == ',' || c == '\n')? + start;
    json[start..end].trim().parse().ok()
}

// ---------------------------------------------------------------------------
// hand-rolled JSON (no serde dependency)
// ---------------------------------------------------------------------------

pub(crate) fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn u32_array(v: &[u32]) -> String {
    let mut s = String::from("[");
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&x.to_string());
    }
    s.push(']');
    s
}

fn usize_array(v: &[usize]) -> String {
    let mut s = String::from("[");
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&x.to_string());
    }
    s.push(']');
    s
}

fn crash_to_json(r: &CrashRecord) -> String {
    format!(
        "{{\n  \"index\": {},\n  \"timestamp\": {:.6},\n  \"signal\": {},\n  \"signame\": \"{}\",\n  \"strategy\": \"{}\",\n  \"seed\": {},\n  \"func\": \"{}\",\n  \"kind\": \"{}\",\n  \"in_len\": {},\n  \"n\": {},\n  \"payload_len\": {},\n  \"timed_out\": {},\n  \"boundary_indices\": {},\n  \"coeffs\": {},\n  \"payload_hex\": \"{}\",\n  \"path\": \"{}\",\n  \"note\": \"{}\"\n}}\n",
        r.index,
        r.timestamp,
        r.signal,
        json_escape(&r.signame),
        json_escape(&r.strategy),
        r.seed,
        json_escape(&r.func),
        json_escape(&r.kind),
        r.in_len,
        r.n,
        r.payload_len,
        r.timed_out,
        usize_array(&r.boundary_indices),
        u32_array(&r.coeffs),
        json_escape(&r.payload_hex),
        json_escape(&r.path),
        json_escape(&r.note),
    )
}

/// One-line `--json` summary: execs/crashes/distinct plus a signal-name
/// breakdown, agreeing with whatever the caller passes as `exit_code`.
pub fn summary_json(s: &FuzzState, signal_counts: &[(String, usize)], exit_code: i32) -> String {
    let mut signals = String::from("{");
    for (i, (name, count)) in signal_counts.iter().enumerate() {
        if i > 0 {
            signals.push(',');
        }
        signals.push_str(&format!("\"{name}\":{count}"));
    }
    signals.push('}');
    format!(
        "{{\"tool\":\"fuzz-lattice\",\"target\":\"{}\",\"symbol\":\"{}\",\"surface\":\"{}\",\"execs\":{},\"crashes\":{},\"distinct\":{},\"signals\":{},\"timeouts\":{},\"exit_code\":{}}}",
        json_escape(&s.target),
        json_escape(&s.symbol),
        s.kind,
        s.execs,
        s.crashes,
        s.unique,
        signals,
        s.timeouts,
        exit_code,
    )
}

// ---------------------------------------------------------------------------
// live view
// ---------------------------------------------------------------------------

fn render(s: &FuzzState, color: bool) -> String {
    let mut o = String::new();
    let p = |c: &str, t: &str| ui::paint(color, c, t);

    o.push_str(&p(&format!("{}{}", ui::BOLD, ui::CYAN), "LatticeScope · structure-aware lattice fuzzer"));
    o.push('\n');
    o.push_str(&format!(
        "  target {}   symbol {}   surface {}   core {}\n\n",
        s.target,
        p(ui::CYAN, &s.symbol),
        s.kind,
        s.core
    ));

    if s.crashes > 0 {
        o.push_str(&p(
            &format!("{}{}", ui::RED_BG, ui::BOLD),
            &format!(
                "  ⚠  MEMORY / ARITHMETIC VIOLATION  —  {} crash(es), {} distinct  ",
                ui::human_int(s.crashes),
                s.unique
            ),
        ));
        o.push_str("\n\n");
    }

    o.push_str(&format!(
        "  execs {}    distinct {}    timeouts {}    strategy: {}\n",
        p(ui::BOLD, &ui::human_int(s.execs)),
        s.unique,
        s.timeouts,
        p(ui::CYAN, &s.current_strategy)
    ));
    o.push_str(&p(
        ui::DIM,
        &format!("  elapsed {:.1}s    rate {}\n\n", s.elapsed, ui::human_rate(s.rate)),
    ));

    if s.recent.is_empty() {
        o.push_str(&p(ui::GREEN, "  no crashes yet — corpus clean under current strategies\n"));
    } else {
        o.push_str(&format!("  {:<10}{:<28}{:<10}{}\n", "signal", "strategy", "seed", "boundary coeffs"));
        for c in &s.recent {
            let sig = if c.signal == libc::SIGSEGV || c.signal == libc::SIGFPE || c.signal == libc::SIGBUS {
                p(ui::RED, &c.signame)
            } else {
                p(ui::YELLOW, &c.signame)
            };
            let nb = c.boundary_indices.len();
            let first = c.boundary_indices.first().map(|i| format!("#{i}")).unwrap_or_default();
            o.push_str(&format!(
                "  {:<10}{:<28}{:<10}{} ({})\n",
                sig,
                truncate(&c.strategy, 26),
                format!("{:#010x}", c.seed),
                first,
                nb
            ));
        }
    }

    if let Some(c) = &s.last_crash {
        o.push('\n');
        o.push_str(&p(ui::DIM, &format!("  last payload {}\n", ui::hex_preview(&hex_to_bytes(&c.payload_hex), 24))));
    }
    o
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

fn hex_to_bytes(h: &str) -> Vec<u8> {
    let clean: String = h.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[2 * i..2 * i + 2], 16).unwrap_or(0))
        .collect()
}

/// Run the fuzzer. Returns the final state; the caller sets the process exit
/// code (2 if any crash was found).
pub fn run(engine: &mut FuzzEngine, iters: u64, batch: u64, refresh_hz: f64) -> FuzzState {
    let color = ui::is_tty();
    let min_period = if refresh_hz > 0.0 { 1.0 / refresh_hz } else { 0.0 };
    let mut last_draw = Instant::now() - std::time::Duration::from_secs(1);
    let out = std::io::stdout();

    while engine.execs < iters {
        engine.step(batch);
        if last_draw.elapsed().as_secs_f64() >= min_period {
            let st = engine.snapshot();
            let mut h = out.lock();
            let _ = write!(h, "{}{}", ui::clear_home(), render(&st, color));
            let _ = h.flush();
            last_draw = Instant::now();
        }
    }
    let final_state = engine.snapshot();
    let mut h = out.lock();
    let _ = writeln!(h, "{}{}", ui::clear_home(), render(&final_state, color));
    let _ = h.flush();
    final_state
}

#[allow(unused)]
fn _fam(p: &Profile) -> Family {
    p.family
}