//! Dependency-free terminal rendering: ANSI colour, a unicode sparkline, bar
//! rows for the twin histogram, and small formatting helpers. Colour is emitted
//! only when stdout is a TTY.

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const CYAN: &str = "\x1b[36m";
pub const RED_BG: &str = "\x1b[41m\x1b[97m";

pub fn is_tty() -> bool {
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}

/// Clear screen + move cursor home (for the live redraw).
pub fn clear_home() -> &'static str {
    "\x1b[2J\x1b[H"
}

pub fn paint(color: bool, code: &str, text: &str) -> String {
    if color {
        format!("{code}{text}{RESET}")
    } else {
        text.to_string()
    }
}

const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

pub fn sparkline(vals: &[f64], width: usize) -> String {
    if vals.is_empty() {
        return String::new();
    }
    let tail = if vals.len() > width {
        &vals[vals.len() - width..]
    } else {
        vals
    };
    let lo = tail.iter().cloned().fold(f64::INFINITY, f64::min);
    let hi = tail.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let span = (hi - lo).max(1e-9);
    tail.iter()
        .map(|&v| {
            let idx = (((v - lo) / span) * (BLOCKS.len() - 1) as f64).round() as usize;
            BLOCKS[idx.min(BLOCKS.len() - 1)]
        })
        .collect()
}

/// A horizontal bar (unicode eighths) scaled to `width` cells.
pub fn hbar(count: u64, max: u64, width: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let frac = count as f64 / max as f64;
    let cells = frac * width as f64;
    let full = cells.floor() as usize;
    let mut s = "█".repeat(full);
    let rem = cells - full as f64;
    if rem > 0.0 && full < width {
        let idx = ((rem * 8.0).round() as usize).clamp(1, 8) - 1;
        s.push(BLOCKS[idx]);
    }
    s
}

pub fn human_int(n: u64) -> String {
    let f = n as f64;
    if f >= 1e9 {
        format!("{:.2}B", f / 1e9)
    } else if f >= 1e6 {
        format!("{:.2}M", f / 1e6)
    } else if f >= 1e3 {
        format!("{:.2}K", f / 1e3)
    } else {
        format!("{n}")
    }
}

pub fn human_rate(r: f64) -> String {
    if r >= 1e6 {
        format!("{:.2}M/s", r / 1e6)
    } else if r >= 1e3 {
        format!("{:.2}K/s", r / 1e3)
    } else {
        format!("{:.0}/s", r)
    }
}

/// Group an integer with thousands separators.
pub fn commas(n: f64) -> String {
    let neg = n < 0.0;
    let s = format!("{:.0}", n.abs());
    let bytes = s.as_bytes();
    let mut out = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    if neg {
        format!("-{out}")
    } else {
        out
    }
}

/// First `max_bytes` of a byte slice as hex (with an ellipsis if truncated).
pub fn hex_preview(data: &[u8], max_bytes: usize) -> String {
    let take = data.len().min(max_bytes);
    let mut s = String::with_capacity(take * 2 + 1);
    for b in &data[..take] {
        s.push_str(&format!("{b:02x}"));
    }
    if data.len() > take {
        s.push('…');
    }
    s
}

/// Full hex encoding (for crash artifacts).
pub fn hex_all(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}