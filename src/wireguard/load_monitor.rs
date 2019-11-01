// Copyright 2017 Guanhao Yin <sopium@mysterious.site>

// This file is part of TiTun.

// TiTun is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// TiTun is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with TiTun.  If not, see <https://www.gnu.org/licenses/>.

use std::time::Instant;
use tokio::time::clock::now;

/// Monitors the frequency of handshake messages and determine whether
/// they are arriving too quickly.
///
/// Implemented with a (deep) token bucket.
pub struct LoadMonitor {
    // Constant. How many messages are allowed every seconds.
    freq: u32,
    // Scaled to 10^9, to match timer precision.
    bucket: u64,
    last_check: Instant,
    under_load: bool,
}

const CAP_RATIO: u64 = 4;

impl LoadMonitor {
    /// Create a new load monitor that allows `freq` messages per second.
    ///
    /// If there are more than `freq` messages per second, it will soon indicate
    /// that we are under load.
    ///
    /// If there are less than `freq` messages per second, it will slowly
    /// but eventually determine that we are no longer under load.
    pub fn new(freq: u32) -> Self {
        LoadMonitor {
            freq,
            bucket: CAP_RATIO * u64::from(freq) * NANOS_PER_SEC,
            last_check: now(),
            under_load: false,
        }
    }

    /// Call this when receiving a message.
    ///
    /// Returns whether we are under load.
    pub fn check(&mut self) -> bool {
        let freq = u64::from(self.freq);
        let cap = CAP_RATIO * freq * NANOS_PER_SEC;

        let now = now();
        let passed = now.duration_since(self.last_check);
        let bucket_add =
            (passed.as_secs() * freq * NANOS_PER_SEC) + u64::from(passed.subsec_nanos()) * freq;
        self.last_check = now;
        self.bucket = std::cmp::min(cap, self.bucket + bucket_add);

        self.bucket = self.bucket.saturating_sub(NANOS_PER_SEC);

        // println!("bucket: {}", self.bucket as f64 / NANOS_PER_SEC as f64);

        if self.under_load {
            if self.bucket >= 7 * cap / 8 {
                self.under_load = false;
                debug!("No longer under load.");
            }
        } else if self.bucket <= 3 * cap / 4 {
            self.under_load = true;
            debug!("Under load!");
        }

        self.under_load
    }
}

const NANOS_PER_SEC: u64 = 1_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn load_monitor() {
        let mut u = LoadMonitor::new(100);

        for _ in 0..110 {
            u.check();
        }

        assert!(u.check());

        sleep(Duration::from_secs(1));

        assert!(!u.check());
    }
}
