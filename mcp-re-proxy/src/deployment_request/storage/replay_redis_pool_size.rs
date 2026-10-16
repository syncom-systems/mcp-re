// SPDX-License-Identifier: Apache-2.0
//! How many connections the Redis replay store holds open.

use std::num::NonZeroUsize;

/// The size of the Redis replay store's connection pool, within the admitted range.
///
/// A sizing parameter, not a security one: every connection runs the same `SET NX PX`
/// and `WAIT` the store's tier declares, and which connection an insert takes never
/// changes its decision. It is bounded because each connection is a server-side client
/// that `WAIT` blocks while its replicas acknowledge, so the pool is how many admissions
/// can wait at once — and an unbounded value is an unbounded number of sockets per
/// replica on a shared Redis.
///
/// The field is private and [`new`](Self::new) is the only checked constructor, so
/// holding one IS the statement that it lies in `1..=MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayRedisPoolSize(NonZeroUsize);

impl ReplayRedisPoolSize {
    /// The largest pool a deployment may declare.
    pub const MAX: usize = 128;

    /// The pool a deployment gets when it declares none.
    pub const DEFAULT: Self = match NonZeroUsize::new(8) {
        Some(size) => Self(size),
        None => panic!("the default replay pool holds at least one connection"),
    };

    /// A pool of `size` connections, refused outside `1..=MAX`.
    pub fn new(size: usize) -> Result<Self, String> {
        NonZeroUsize::new(size)
            .filter(|size| size.get() <= Self::MAX)
            .map(Self)
            .ok_or_else(|| {
                format!(
                    "--replay-redis-pool-size must be between 1 and {}, got {size}",
                    Self::MAX
                )
            })
    }

    /// `--replay-redis-pool-size`, as typed.
    pub fn parse(value: &str) -> Result<Self, String> {
        let size = value.parse().map_err(|_| {
            format!(
                "--replay-redis-pool-size must be an integer between 1 and {}, got {value:?}",
                Self::MAX
            )
        })?;
        Self::new(size)
    }

    /// The number of connections.
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_admitted_range_is_one_through_max() {
        for size in [1, 8, 16, 32, ReplayRedisPoolSize::MAX] {
            let pool = ReplayRedisPoolSize::new(size)
                .unwrap_or_else(|e| panic!("{size} is admitted: {e}"));
            assert_eq!(pool.get(), size);
        }
        for size in [0, ReplayRedisPoolSize::MAX + 1, 1024] {
            let err = ReplayRedisPoolSize::new(size).expect_err("outside the range");
            assert!(err.contains("between 1 and 128"), "{err}");
        }
    }

    #[test]
    fn the_default_is_the_eight_connection_pool() {
        assert_eq!(ReplayRedisPoolSize::DEFAULT.get(), 8);
    }

    #[test]
    fn parse_refuses_non_integers_and_out_of_range_values() {
        assert_eq!(
            ReplayRedisPoolSize::parse("32").map(ReplayRedisPoolSize::get),
            Ok(32)
        );
        for value in ["", "eight", "-1", "1.5", " 8"] {
            let err = ReplayRedisPoolSize::parse(value).expect_err("not an integer");
            assert!(err.contains("must be an integer"), "{value:?}: {err}");
        }
        for value in ["0", "129"] {
            let err = ReplayRedisPoolSize::parse(value).expect_err("out of range");
            assert!(err.contains("between 1 and 128"), "{value:?}: {err}");
        }
    }
}
