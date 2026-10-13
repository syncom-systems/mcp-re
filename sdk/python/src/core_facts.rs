// SPDX-License-Identifier: Apache-2.0
//! What the native core reports about itself: the audited core's version, the profile tag it
//! signs and verifies under, and the clock-skew bound it enforces. Facts, not calls: nothing
//! here marshals arguments, and the host reads them to derive its own windows and labels
//! from the numbers the core holds rather than restating them.

use pyo3::prelude::*;

/// The audited core's version — `mcp-re-client-core`'s, not this binding crate's.
#[pyfunction]
fn core_version() -> &'static str {
    mcp_re_binding_core::CORE_VERSION
}

/// The RFC 9421 profile tag the signature is emitted/verified under.
#[pyfunction]
fn profile_tag() -> &'static str {
    mcp_re_binding_core::PROFILE_TAG
}

/// The widest clock-skew tolerance, in seconds, a verification call accepts.
#[pyfunction]
fn max_clock_skew_bound() -> i64 {
    mcp_re_binding_core::MAX_CLOCK_SKEW_BOUND_SECS
}

/// Add the three facts to the module.
pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    m.add_function(wrap_pyfunction!(profile_tag, m)?)?;
    m.add_function(wrap_pyfunction!(max_clock_skew_bound, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::core_version;
    use super::max_clock_skew_bound;
    use super::profile_tag;

    #[test]
    fn each_fact_is_the_binding_cores_own() {
        assert_eq!(core_version(), mcp_re_binding_core::CORE_VERSION);
        assert_eq!(profile_tag(), mcp_re_binding_core::PROFILE_TAG);
        assert_eq!(
            max_clock_skew_bound(),
            mcp_re_binding_core::MAX_CLOCK_SKEW_BOUND_SECS
        );
    }
}
