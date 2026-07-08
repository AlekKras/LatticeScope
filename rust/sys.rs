//! Thin, audited wrappers over the handful of libc facilities LatticeScope
//! needs: dynamic loading of the target, the cycle counter, CPU pinning, and a
//! fork/timeout primitive for the fuzzer.
//!
//! ## Why the fuzzer's timeout is built on `sigtimedwait`
//!
//! A common (and subtly wrong) way to bound a blocking `waitpid` is to arm a
//! `SIGALRM` handler that raises, so the syscall is interrupted. That design
//! has a race: if the child exits at almost exactly the deadline, the alarm can
//! fire in the window *after* `waitpid` returns but *before* the timer is
//! disarmed, and the stray signal escapes.
//!
//! Here we instead **block `SIGCHLD`** process-wide up front and wait for it
//! with `sigtimedwait`. Because the signal is blocked, a child that dies before
//! we start waiting leaves `SIGCHLD` *pending* rather than lost, and
//! `sigtimedwait` returns it atomically. There is no handler, no timer to
//! disarm, and therefore no race. On timeout we `SIGKILL` and reap.

use std::ffi::{CStr, CString};
use std::os::raw::c_void;
use std::time::{Duration, Instant};

// ----------------------------------------------------------------------------
// errno / dlerror helpers
// ----------------------------------------------------------------------------

#[inline]
fn errno() -> i32 {
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location()
    }
    #[cfg(not(target_os = "linux"))]
    unsafe {
        *libc::__error()
    }
}

fn dlerror_string() -> String {
    unsafe {
        let e = libc::dlerror();
        if e.is_null() {
            "unknown dynamic-linker error".to_string()
        } else {
            CStr::from_ptr(e).to_string_lossy().into_owned()
        }
    }
}

// ----------------------------------------------------------------------------
// Dynamic library loading (RAII)
// ----------------------------------------------------------------------------

/// An `dlopen`ed shared object. Symbols resolved from it are only valid while
/// this handle is alive.
pub struct DynLib {
    handle: *mut c_void,
    pub name: String,
}

impl DynLib {
    pub fn open(path: &str) -> Result<DynLib, String> {
        let c = CString::new(path).map_err(|_| "target path contains a NUL byte".to_string())?;
        let handle = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(format!("dlopen({path}) failed: {}", dlerror_string()));
        }
        Ok(DynLib { handle, name: path.to_string() })
    }

    /// Resolve an exported symbol to its address. A missing symbol is an error
    /// (we distinguish it from a legitimately-NULL symbol via `dlerror`).
    pub fn symbol(&self, name: &str) -> Result<*const c_void, String> {
        let c = CString::new(name).map_err(|_| "symbol name contains a NUL byte".to_string())?;
        unsafe {
            libc::dlerror(); // clear any stale error
            let p = libc::dlsym(self.handle, c.as_ptr());
            let err = libc::dlerror();
            if !err.is_null() {
                return Err(format!(
                    "symbol '{name}' not found in {}: {}",
                    self.name,
                    CStr::from_ptr(err).to_string_lossy()
                ));
            }
            Ok(p as *const c_void)
        }
    }
}

impl Drop for DynLib {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self.handle);
        }
    }
}

// ----------------------------------------------------------------------------
// Cycle counter
// ----------------------------------------------------------------------------
//
// The counter is read *inside Rust*, immediately around the indirect call to
// the target. No FFI-to-our-own-C and no interpreter sit inside the measured
// window — only the target call does.
//
// x86_64:  LFENCE; RDTSC (begin) and LFENCE; RDTSCP; LFENCE (end). LFENCE is a
//          real serialising fence and the PIC-safe alternative to CPUID+RDTSC
//          (CPUID clobbers RBX, which fights position-independent code).
// aarch64: ISB around CNTVCT_EL0 (a fixed-frequency virtual counter, not core
//          cycles — hence the honest unit label).
// other:   CLOCK_MONOTONIC nanoseconds, so the tool still runs everywhere.
//
// N.B. RDTSC reads the invariant TSC: "reference cycles" at the nominal base
// frequency, independent of turbo/throttle. That is exactly what dudect-style
// differential timing wants, but it is why the unit reads "TSC" rather than
// pretending to be core clocks.

#[cfg(target_arch = "x86_64")]
pub mod counter {
    use core::arch::x86_64::{__rdtscp, _mm_lfence, _rdtsc};
    pub const UNIT: &str = "cycles (TSC)";

    #[inline(always)]
    pub fn begin() -> u64 {
        unsafe {
            _mm_lfence();
            let t = _rdtsc();
            _mm_lfence();
            t
        }
    }

    #[inline(always)]
    pub fn end() -> u64 {
        let mut aux: u32 = 0;
        unsafe {
            _mm_lfence();
            let t = __rdtscp(&mut aux);
            _mm_lfence();
            core::hint::black_box(aux);
            t
        }
    }
}

#[cfg(target_arch = "aarch64")]
pub mod counter {
    pub const UNIT: &str = "ticks (CNTVCT)";

    #[inline(always)]
    pub fn begin() -> u64 {
        let v: u64;
        unsafe {
            core::arch::asm!("isb", "mrs {v}, cntvct_el0", v = out(reg) v);
        }
        v
    }

    #[inline(always)]
    pub fn end() -> u64 {
        let v: u64;
        unsafe {
            core::arch::asm!("mrs {v}, cntvct_el0", "isb", v = out(reg) v);
        }
        v
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub mod counter {
    pub const UNIT: &str = "ns (CLOCK_MONOTONIC)";

    #[inline(always)]
    fn now_ns() -> u64 {
        unsafe {
            let mut ts: libc::timespec = core::mem::zeroed();
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
            (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
        }
    }

    #[inline(always)]
    pub fn begin() -> u64 {
        now_ns()
    }
    #[inline(always)]
    pub fn end() -> u64 {
        now_ns()
    }
}

/// Median cost of an empty begin..end pair, in counter units. For a *fixed vs
/// random* differential test this cancels between the two classes; it is
/// reported so the operator can sanity-check the measurement scale.
pub fn measure_overhead(samples: usize) -> u64 {
    let mut v: Vec<u64> = Vec::with_capacity(samples);
    for _ in 0..samples {
        let s = counter::begin();
        let e = counter::end();
        v.push(e.saturating_sub(s));
    }
    v.sort_unstable();
    v[v.len() / 2]
}

// ----------------------------------------------------------------------------
// CPU pinning
// ----------------------------------------------------------------------------

/// Pin the calling thread to a single logical CPU. Returns false if the OS
/// refuses (or on non-Linux). Best-effort: the tool runs unpinned too.
#[cfg(target_os = "linux")]
pub fn pin_cpu(core: usize) -> bool {
    unsafe {
        let mut set: libc::cpu_set_t = core::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core, &mut set);
        libc::sched_setaffinity(0, core::mem::size_of::<libc::cpu_set_t>(), &set) == 0
    }
}

// ponytail: sched_setaffinity has no portable equivalent (macOS's thread affinity
// API is a soft hint, not a hard pin); non-Linux just runs unpinned.
#[cfg(not(target_os = "linux"))]
pub fn pin_cpu(_core: usize) -> bool {
    false
}

// ----------------------------------------------------------------------------
// Fork / timeout reaper
// ----------------------------------------------------------------------------

/// How a forked child terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Exited normally with this status code.
    Exited(i32),
    /// Killed by this signal number (SIGSEGV, SIGFPE, ...).
    Signaled(i32),
    /// Exceeded the wall-clock budget; we SIGKILLed it.
    TimedOut,
    /// `fork` itself failed.
    ForkFailed,
}

/// Owns the process-wide `SIGCHLD` block. Create one before fuzzing.
pub struct Reaper {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    chld: libc::sigset_t,
}

impl Reaper {
    pub fn new() -> Reaper {
        unsafe {
            let mut set: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGCHLD);
            // Block SIGCHLD so a child that dies before we wait leaves it
            // pending rather than lost.
            libc::sigprocmask(libc::SIG_BLOCK, &set, core::ptr::null_mut());
            Reaper { chld: set }
        }
    }

    /// Fork; run `child` in the child process (it must not return — we `_exit`
    /// for it), and in the parent wait up to `timeout` for it to finish.
    ///
    /// # Safety
    /// `fork` in a process with multiple threads is unsound; LatticeScope's
    /// fuzz loop is single-threaded by construction. Between fork and exit the
    /// child runs only `child()` (one indirect call into the target) — no Rust
    /// allocation or locking on our side.
    pub unsafe fn run<F: FnOnce()>(&self, timeout: Duration, child: F) -> Outcome {
        let pid = libc::fork();
        if pid < 0 {
            return Outcome::ForkFailed;
        }
        if pid == 0 {
            // ---- child ----
            child();
            libc::_exit(0);
        }

        // ---- parent ----
        let deadline = Instant::now() + timeout;

        #[cfg(target_os = "linux")]
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let ts = libc::timespec {
                tv_sec: remaining.as_secs() as libc::time_t,
                tv_nsec: remaining.subsec_nanos() as libc::c_long,
            };
            let sig = libc::sigtimedwait(&self.chld, core::ptr::null_mut(), &ts);
            if sig == libc::SIGCHLD {
                return reap(pid);
            }
            match errno() {
                libc::EINTR => continue, // interrupted by some other signal; retry
                _ => {
                    // EAGAIN: the deadline expired without the child exiting.
                    libc::kill(pid, libc::SIGKILL);
                    let _ = reap(pid); // collect the corpse; don't leak a zombie
                    return Outcome::TimedOut;
                }
            }
        }

        // ponytail: sigtimedwait doesn't exist outside Linux/glibc, so there's no
        // way here to wait on the *pending* SIGCHLD atomically. Poll waitpid(WNOHANG)
        // instead; SIGCHLD stays blocked so it can't race a handler. Upgrade to
        // kqueue's EVFILT_SIGNAL if the poll interval ever shows up in a profile.
        #[cfg(not(target_os = "linux"))]
        loop {
            let mut status: libc::c_int = 0;
            let r = libc::waitpid(pid, &mut status, libc::WNOHANG);
            if r == pid {
                return interpret(status);
            }
            if Instant::now() >= deadline {
                libc::kill(pid, libc::SIGKILL);
                let _ = reap(pid); // collect the corpse; don't leak a zombie
                return Outcome::TimedOut;
            }
            std::thread::sleep(Duration::from_micros(200));
        }
    }
}

unsafe fn interpret(status: libc::c_int) -> Outcome {
    if libc::WIFSIGNALED(status) {
        Outcome::Signaled(libc::WTERMSIG(status))
    } else if libc::WIFEXITED(status) {
        Outcome::Exited(libc::WEXITSTATUS(status))
    } else {
        Outcome::Exited(-1)
    }
}

unsafe fn reap(pid: libc::pid_t) -> Outcome {
    let mut status: libc::c_int = 0;
    loop {
        let r = libc::waitpid(pid, &mut status, 0);
        if r < 0 && errno() == libc::EINTR {
            continue;
        }
        break;
    }
    interpret(status)
}

// ----------------------------------------------------------------------------
// Fork server (opt-in, higher-throughput alternative to one-fork-per-exec)
// ----------------------------------------------------------------------------
//
// The target is already `dlopen`'d once in the parent, so its constructors
// already run only once even on the per-exec path — an AFL-style server can't
// win by skipping re-`exec`, because nothing here ever re-`exec`s. What it can
// win is forking from a small, static process (blocked on a pipe read, never
// allocating) instead of from the top-level parent, whose heap keeps growing
// over a long run (crash records, UI history, RNG state). The server still
// forks exactly one worker per exec — crash isolation is unchanged — through
// the SAME `Reaper` the non-server path uses, so Invariant 2's sigtimedwait
// discipline is reused verbatim, not reimplemented.
//
// Only the per-exec *payload* needs to cross the fork boundary each round, so
// that is the one thing that lives in a `MAP_SHARED` region; the output/key
// buffers are plain (COW) memory exactly as in the non-server path, since
// nothing ever reads them back after the call.

use std::mem::size_of;

/// A `MAP_SHARED` anonymous region: the parent's writes are visible to every
/// process it forks afterward, at the same address, with no IPC needed to
/// propagate them — only to signal "the write already happened".
pub struct SharedBuf {
    ptr: *mut u8,
    len: usize,
}

impl SharedBuf {
    fn new(len: usize) -> Result<SharedBuf, String> {
        let len = len.max(1);
        unsafe {
            let ptr = libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(format!("mmap failed (errno {})", errno()));
            }
            Ok(SharedBuf { ptr: ptr as *mut u8, len })
        }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Copy `data` in, truncated to the region's capacity (the caller sizes
    /// the region to the run's fixed payload length up front, so truncation
    /// is not expected to trigger in practice).
    pub fn write(&self, data: &[u8]) {
        let n = data.len().min(self.len);
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr, n);
        }
    }
}

impl Drop for SharedBuf {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut c_void, self.len);
        }
    }
}

fn make_pipe() -> Result<(i32, i32), String> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!("pipe() failed (errno {})", errno()));
    }
    Ok((fds[0], fds[1]))
}

/// `Outcome`, flattened to two `i32`s so it can cross the status pipe as
/// fixed-size bytes with no serialisation dependency.
#[repr(C)]
#[derive(Clone, Copy)]
struct WireStatus {
    kind: i32, // 0 Exited, 1 Signaled, 2 TimedOut, 3 ForkFailed
    value: i32,
}

fn encode(o: Outcome) -> WireStatus {
    match o {
        Outcome::Exited(c) => WireStatus { kind: 0, value: c },
        Outcome::Signaled(s) => WireStatus { kind: 1, value: s },
        Outcome::TimedOut => WireStatus { kind: 2, value: 0 },
        Outcome::ForkFailed => WireStatus { kind: 3, value: 0 },
    }
}

fn decode(w: WireStatus) -> Outcome {
    match w.kind {
        0 => Outcome::Exited(w.value),
        1 => Outcome::Signaled(w.value),
        2 => Outcome::TimedOut,
        _ => Outcome::ForkFailed,
    }
}

/// A persistent fork-server, forked once after the target is loaded. Forks
/// one worker per exec and relays that worker's `Outcome` back over a pipe.
pub struct ForkServer {
    pid: libc::pid_t,
    ctrl_w: i32,
    status_r: i32,
    pub payload: SharedBuf,
}

impl ForkServer {
    /// Spawn the server. `make_run_once` receives the shared payload
    /// region's address and builds the closure the server will invoke once
    /// per "go" (inside a freshly-forked worker) — that closure should read
    /// its input from the given pointer each time, since the region's
    /// *contents* change every round even though its address does not.
    ///
    /// # Safety
    /// Same contract as `Reaper::run`: the closure `make_run_once` builds
    /// must do nothing beyond the one indirect call into the target between
    /// fork and `_exit` — no Rust allocation or locking in that window. Must
    /// be called after the target is already `dlopen`'d.
    pub unsafe fn spawn<F, M>(
        payload_len: usize,
        timeout: Duration,
        make_run_once: M,
    ) -> Result<ForkServer, String>
    where
        F: Fn() + 'static,
        M: FnOnce(*const u8) -> F,
    {
        let payload = SharedBuf::new(payload_len)?;
        let run_once = make_run_once(payload.as_ptr());
        let (ctrl_r, ctrl_w) = make_pipe()?;
        let (status_r, status_w) = make_pipe()?;

        let pid = libc::fork();
        if pid < 0 {
            return Err("fork (server) failed".to_string());
        }
        if pid == 0 {
            // ---- server ----
            libc::close(ctrl_w);
            libc::close(status_r);
            let reaper = Reaper::new(); // idempotent: SIGCHLD is already blocked
            let mut go = [0u8; 1];
            loop {
                let n = libc::read(ctrl_r, go.as_mut_ptr() as *mut c_void, 1);
                if n <= 0 {
                    libc::_exit(0); // control pipe closed: parent is shutting us down
                }
                let outcome = reaper.run(timeout, || run_once());
                let ws = encode(outcome);
                let buf = &ws as *const WireStatus as *const c_void;
                if libc::write(status_w, buf, size_of::<WireStatus>()) < 0 {
                    libc::_exit(1);
                }
            }
        }

        // ---- parent ----
        libc::close(ctrl_r);
        libc::close(status_w);
        Ok(ForkServer { pid, ctrl_w, status_r, payload })
    }

    /// Run one exec: the caller has already written the payload into
    /// `self.payload`. Blocks until the server relays the worker's outcome.
    pub fn exec(&self) -> Outcome {
        unsafe {
            let go = [1u8];
            if libc::write(self.ctrl_w, go.as_ptr() as *const c_void, 1) != 1 {
                panic!("fork-server: control pipe write failed; server died?");
            }
            let mut ws = WireStatus { kind: -1, value: 0 };
            let want = size_of::<WireStatus>();
            let got = libc::read(self.status_r, &mut ws as *mut WireStatus as *mut c_void, want);
            if got != want as isize {
                panic!("fork-server: status pipe read failed/short; server died?");
            }
            decode(ws)
        }
    }
}

impl Drop for ForkServer {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.ctrl_w); // EOF tells the server to shut down
            let mut status: libc::c_int = 0;
            libc::waitpid(self.pid, &mut status, 0);
            libc::close(self.status_r);
        }
    }
}