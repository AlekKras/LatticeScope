//! Module 1 — microarchitectural timing-leakage detection.
//!
//! The engine drives the target through a fixed-vs-random interleave, timing
//! each call *in Rust* with the cycle counter immediately around the indirect
//! call (see `sys::counter`). It maintains the streaming Welch statistic over
//! the whole run plus a tail-robust cropped statistic over a recent window, and
//! renders a live terminal view.

use crate::profiles::{Family, Profile};
use crate::stats::{welch, Online, TResult, TailWindow, THRESHOLD};
use crate::sys::{counter, DynLib};
use crate::ui;
use std::io::Write;
use std::os::raw::c_int;
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Dec,
    Enc,
    Verify,
}

impl Op {
    pub fn parse(s: &str) -> Option<Op> {
        match s {
            "dec" => Some(Op::Dec),
            "enc" => Some(Op::Enc),
            "verify" => Some(Op::Verify),
            _ => None,
        }
    }
    fn label(&self) -> &'static str {
        match self {
            Op::Dec => "dec",
            Op::Enc => "enc",
            Op::Verify => "verify",
        }
    }
}

type KemDecFn = unsafe extern "C" fn(*mut u8, *const u8, *const u8) -> c_int;
type KemEncFn = unsafe extern "C" fn(*mut u8, *mut u8, *const u8) -> c_int;
type SignVerifyFn =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8) -> c_int;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Collecting,
    CleanSoFar,
    Leak,
}

pub struct TvlaState {
    pub target: String,
    pub symbol: String,
    pub op: &'static str,
    pub core: i32,
    pub unit: &'static str,
    pub overhead: u64,
    pub iters: u64,
    pub n_a: u64,
    pub n_b: u64,
    pub raw: TResult,
    pub robust: TResult,
    pub robust_frac: f64,
    pub best_abs_t: f64,
    pub verdict: Verdict,
    pub rate: f64,
    pub elapsed: f64,
    pub t_history: Vec<f64>,
    pub hist: Vec<(f64, u64, u64)>, // (bin center, count A, count B)
    pub last_rc: i32,
}

pub struct TvlaEngine {
    _lib: DynLib, // kept alive so the fn pointer stays valid
    fptr: *const std::os::raw::c_void,
    op: Op,
    symbol: String,
    target_name: String,
    core: i32,
    unit: &'static str,
    overhead: u64,

    // buffers
    varying_len: usize,
    varying_fixed: Vec<u8>,   // class A input (fixed)
    varying_scratch: Vec<u8>, // class B input (random, refilled each call)
    key_a: Vec<u8>,           // sk / pk / m depending on op
    key_b: Vec<u8>,           // pk for verify (message is key_a)
    out0: Vec<u8>,            // ss (dec) / ct (enc) / unused (verify)
    out1: Vec<u8>,            // ss (enc)
    m_len: usize,

    // statistics
    acc_a: Online,
    acc_b: Online,
    window: TailWindow,
    best_abs_t: f64,
    t_history: Vec<f64>,
    iters: u64,
    last_rc: i32,
    rng: crate::mutators::Rng,

    // timing/rate
    t0: Instant,
    last_snap_time: Instant,
    last_snap_iters: u64,
    last_rate: f64,
}

impl TvlaEngine {
    pub fn new(
        target: &str,
        profile: &Profile,
        op: Op,
        symbol_override: Option<&str>,
        core: i32,
        reservoir: usize,
        seed: u64,
    ) -> Result<TvlaEngine, String> {
        let symbol = match symbol_override {
            Some(s) => s.to_string(),
            None => {
                let s = match op {
                    Op::Dec => profile.sym_dec,
                    Op::Enc => profile.sym_enc,
                    Op::Verify => profile.sym_verify,
                };
                if s.is_empty() {
                    return Err(format!(
                        "profile '{}' has no default symbol for op '{}'; pass --symbol",
                        profile.name,
                        op.label()
                    ));
                }
                s.to_string()
            }
        };

        let lib = DynLib::open(target)?;
        let fptr = lib.symbol(&symbol)?;
        let target_name = std::path::Path::new(target)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| target.to_string());

        if core >= 0 {
            crate::sys::pin_cpu(core as usize);
        }
        let overhead = crate::sys::measure_overhead(4096);

        // Buffer sizing per op.
        let (varying_len, key_a_len, key_b_len, out0_len, out1_len, m_len) = match op {
            Op::Dec => (profile.ct_len.max(1), profile.sk_len.max(1), 0, profile.ss_len.max(32), 0, 0),
            Op::Enc => (profile.pk_len.max(1), 0, 0, profile.ct_len.max(1), profile.ss_len.max(32), 0),
            Op::Verify => {
                let m = 32usize;
                (profile.sig_len.max(1), m, profile.pk_len.max(1), 0, 0, m)
            }
        };

        // Deterministic fixed material.
        let mut seed_rng = crate::mutators::Rng::new(seed ^ 0xA5A5_5A5A_1234_9876);
        let fill = |rng: &mut crate::mutators::Rng, n: usize| -> Vec<u8> {
            (0..n).map(|_| (rng.next_u64() & 0xFF) as u8).collect()
        };

        let varying_fixed = fill(&mut seed_rng, varying_len);
        let key_a = fill(&mut seed_rng, key_a_len);
        let key_b = fill(&mut seed_rng, key_b_len);

        Ok(TvlaEngine {
            _lib: lib,
            fptr,
            op,
            symbol,
            target_name,
            core,
            unit: counter::UNIT,
            overhead,
            varying_len,
            varying_fixed,
            varying_scratch: vec![0u8; varying_len],
            key_a,
            key_b,
            out0: vec![0u8; out0_len],
            out1: vec![0u8; out1_len],
            m_len,
            acc_a: Online::new(),
            acc_b: Online::new(),
            window: TailWindow::new(reservoir),
            best_abs_t: 0.0,
            t_history: Vec::with_capacity(300),
            iters: 0,
            last_rc: 0,
            rng: crate::mutators::Rng::new(seed),
            t0: Instant::now(),
            last_snap_time: Instant::now(),
            last_snap_iters: 0,
            last_rate: 0.0,
        })
    }

    /// One timed measurement of the given class. Returns (cycles, rc).
    unsafe fn measure(&mut self, class_b: bool) -> (u64, c_int) {
        // Prepare the varying input.
        let inbuf: *const u8 = if class_b {
            for byte in self.varying_scratch.iter_mut() {
                *byte = (self.rng.next_u64() & 0xFF) as u8;
            }
            self.varying_scratch.as_ptr()
        } else {
            self.varying_fixed.as_ptr()
        };

        match self.op {
            Op::Dec => {
                let f: KemDecFn = std::mem::transmute(self.fptr);
                let ss = self.out0.as_mut_ptr();
                let sk = self.key_a.as_ptr();
                let s = counter::begin();
                let rc = f(ss, inbuf, sk);
                let e = counter::end();
                core::hint::black_box(ss);
                (e.saturating_sub(s), rc)
            }
            Op::Enc => {
                let f: KemEncFn = std::mem::transmute(self.fptr);
                let ct = self.out0.as_mut_ptr();
                let ss = self.out1.as_mut_ptr();
                // `inbuf` is pk here.
                let s = counter::begin();
                let rc = f(ct, ss, inbuf);
                let e = counter::end();
                core::hint::black_box(ct);
                (e.saturating_sub(s), rc)
            }
            Op::Verify => {
                let f: SignVerifyFn = std::mem::transmute(self.fptr);
                let sig = inbuf;
                let siglen = self.varying_len;
                let m = self.key_a.as_ptr();
                let mlen = self.m_len;
                let pk = self.key_b.as_ptr();
                let s = counter::begin();
                let rc = f(sig, siglen, m, mlen, pk);
                let e = counter::end();
                (e.saturating_sub(s), rc)
            }
        }
    }

    pub fn prime(&mut self, warmup: u64) {
        for _ in 0..warmup {
            unsafe {
                let _ = self.measure(false);
                let _ = self.measure(true);
            }
        }
    }

    pub fn step(&mut self, n: u64) {
        for _ in 0..n {
            let class_b = self.rng.coin();
            let (cycles, rc) = unsafe { self.measure(class_b) };
            let v = cycles as f64;
            if class_b {
                self.acc_b.push(v);
                self.window.push(1, v);
            } else {
                self.acc_a.push(v);
                self.window.push(0, v);
            }
            self.last_rc = rc;
            self.iters += 1;
        }
    }

    pub fn snapshot(&mut self) -> TvlaState {
        let raw = welch(&self.acc_a, &self.acc_b);
        let (robust, frac) = self.window.evaluate();
        let best = raw.t.abs().max(robust.t.abs());
        self.best_abs_t = self.best_abs_t.max(best);

        self.t_history.push(robust.t.abs());
        if self.t_history.len() > 300 {
            self.t_history.remove(0);
        }

        // Rate, holding the last good value when no new work has occurred (so
        // the post-loop summary frame never reports 0/s).
        let now = Instant::now();
        let dt = now.duration_since(self.last_snap_time).as_secs_f64();
        let di = self.iters - self.last_snap_iters;
        let rate = if dt > 1e-3 && di > 0 {
            let r = di as f64 / dt;
            self.last_rate = r;
            self.last_snap_time = now;
            self.last_snap_iters = self.iters;
            r
        } else {
            self.last_rate
        };

        let verdict = if self.acc_a.n < 1000 || self.acc_b.n < 1000 {
            Verdict::Collecting
        } else if best > THRESHOLD {
            Verdict::Leak
        } else {
            Verdict::CleanSoFar
        };

        TvlaState {
            target: self.target_name.clone(),
            symbol: self.symbol.clone(),
            op: self.op.label(),
            core: self.core,
            unit: self.unit,
            overhead: self.overhead,
            iters: self.iters,
            n_a: self.acc_a.n,
            n_b: self.acc_b.n,
            hist: self.build_histogram(&raw),
            raw,
            robust,
            robust_frac: frac,
            best_abs_t: self.best_abs_t,
            verdict,
            rate,
            elapsed: now.duration_since(self.t0).as_secs_f64(),
            t_history: self.t_history.clone(),
            last_rc: self.last_rc,
        }
    }

    fn build_histogram(&self, raw: &TResult) -> Vec<(f64, u64, u64)> {
        const BINS: usize = 22;
        // Range from the class means ± a few std devs, so the useful mass fills
        // the view rather than being squashed by the tail.
        let mean = (raw.mean_a + raw.mean_b) / 2.0;
        let sd = (raw.var_a.max(raw.var_b)).sqrt().max(1.0);
        let lo = (mean - 3.0 * sd).max(0.0);
        let hi = mean + 5.0 * sd;
        let span = (hi - lo).max(1.0);
        let mut a = vec![0u64; BINS];
        let mut b = vec![0u64; BINS];
        // The window holds recent (class, value) pairs.
        self.window.for_each(|cls, v| {
            if v < lo || v > hi {
                return;
            }
            let idx = (((v - lo) / span) * BINS as f64) as usize;
            let idx = idx.min(BINS - 1);
            if cls == 0 {
                a[idx] += 1;
            } else {
                b[idx] += 1;
            }
        });
        (0..BINS)
            .map(|i| {
                let center = lo + (i as f64 + 0.5) * span / BINS as f64;
                (center, a[i], b[i])
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// live view
// ---------------------------------------------------------------------------

fn render(s: &TvlaState, color: bool) -> String {
    let mut o = String::new();
    let p = |c: &str, t: &str| ui::paint(color, c, t);

    o.push_str(&p(&format!("{}{}", ui::BOLD, ui::CYAN), "LatticeScope · TVLA timing-leakage detector"));
    o.push('\n');
    o.push_str(&format!("  target {}   symbol {}\n", s.target, p(ui::CYAN, &s.symbol)));
    o.push_str(&format!(
        "  op {}   core {}   unit {}   overhead {}\n\n",
        s.op, s.core, s.unit, s.overhead
    ));

    o.push_str(&format!("  {:14}{:>18}{:>20}\n", "", "Class A (fixed)", "Class B (random)"));
    o.push_str(&format!(
        "  {:14}{:>18}{:>20}\n",
        "samples",
        ui::human_int(s.n_a),
        ui::human_int(s.n_b)
    ));
    o.push_str(&format!(
        "  {:14}{:>18}{:>20}\n",
        "mean",
        ui::commas(s.raw.mean_a),
        ui::commas(s.raw.mean_b)
    ));
    o.push_str(&format!(
        "  {:14}{:>18}{:>20}\n\n",
        "variance",
        ui::commas(s.raw.var_a),
        ui::commas(s.raw.var_b)
    ));

    o.push_str(&format!(
        "  t(raw)     {:+.3}   dof {}   95%CI [{:+}, {:+}]\n",
        s.raw.t,
        ui::commas(s.raw.dof),
        ui::commas(s.raw.ci_low),
        ui::commas(s.raw.ci_high)
    ));
    o.push_str(&format!(
        "  t(robust)  {:+.3}   keep {:.0}%   max|t| {:.3}   thr |t|>{}\n\n",
        s.robust.t,
        s.robust_frac * 100.0,
        s.best_abs_t,
        THRESHOLD
    ));

    o.push_str(&format!("  |t| {}\n\n", ui::sparkline(&s.t_history, 54)));

    o.push_str(&format!("  {:>10}  A / B distributions\n", "cycles"));
    let maxc = s
        .hist
        .iter()
        .map(|&(_, a, b)| a.max(b))
        .max()
        .unwrap_or(1)
        .max(1);
    for &(center, ca, cb) in &s.hist {
        let bar_a = ui::hbar(ca, maxc, 18);
        let bar_b = ui::hbar(cb, maxc, 18);
        o.push_str(&format!("  {:>10}  {}\n", ui::commas(center), p(ui::GREEN, &bar_a)));
        o.push_str(&format!("  {:>10}  {}\n", "", p(ui::YELLOW, &bar_b)));
    }
    o.push('\n');

    let verdict_line = match s.verdict {
        Verdict::Leak => p(&format!("{}{}", ui::RED_BG, ui::BOLD), &format!("  VERDICT: LEAK  (|t|={:.2})  ", s.best_abs_t)),
        Verdict::CleanSoFar => p(ui::GREEN, &format!("  VERDICT: clean so far  (|t|={:.2})", s.best_abs_t)),
        Verdict::Collecting => p(ui::YELLOW, "  VERDICT: collecting"),
    };
    o.push_str(&verdict_line);
    o.push('\n');
    o.push_str(&p(
        ui::DIM,
        &format!(
            "  iters {}   elapsed {:.1}s   rate {}   rc={}",
            ui::human_int(s.iters),
            s.elapsed,
            ui::human_rate(s.rate),
            s.last_rc
        ),
    ));
    o
}

/// Run the engine to `iters`, redrawing at up to `refresh_hz`. Returns the
/// final state. Exit-worthy result is in `state.verdict`.
pub fn run(engine: &mut TvlaEngine, iters: u64, batch: u64, warmup: u64, refresh_hz: f64) -> TvlaState {
    let color = ui::is_tty();
    let min_period = if refresh_hz > 0.0 { 1.0 / refresh_hz } else { 0.0 };
    engine.prime(warmup);

    let mut last_draw = Instant::now() - std::time::Duration::from_secs(1);
    let out = std::io::stdout();
    while engine.iters < iters {
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

/// One-line `--json` summary: verdict plus raw/robust t and sample sizes,
/// agreeing with whatever the caller passes as `exit_code`.
pub fn summary_json(s: &TvlaState, exit_code: i32) -> String {
    let verdict = match s.verdict {
        Verdict::Leak => "leak",
        Verdict::CleanSoFar => "clean",
        Verdict::Collecting => "collecting",
    };
    format!(
        "{{\"tool\":\"tvla\",\"target\":\"{}\",\"symbol\":\"{}\",\"op\":\"{}\",\"verdict\":\"{}\",\"t_raw\":{:.6},\"t_robust\":{:.6},\"n_a\":{},\"n_b\":{},\"iters\":{},\"exit_code\":{}}}",
        crate::fuzz::json_escape(&s.target),
        crate::fuzz::json_escape(&s.symbol),
        s.op,
        verdict,
        s.raw.t,
        s.robust.t,
        s.n_a,
        s.n_b,
        s.iters,
        exit_code,
    )
}

// unused import guard
#[allow(unused)]
fn _fam(_p: &Profile) -> Family {
    _p.family
}