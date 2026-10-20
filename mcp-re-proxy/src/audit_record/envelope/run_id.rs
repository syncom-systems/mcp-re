// SPDX-License-Identifier: Apache-2.0
//! The identity of one process's audit run.

/// One run of the process: 128 bits from the OS CSPRNG, drawn once.
///
/// Nothing on an audit record identifies a run. `at=` is wall-clock time, which two runs can
/// share and an operator can set. The process id is reused, and is the same value in every
/// container. The delegated key id rotates within a run and the trust epoch spans the fleet,
/// so neither marks one process. Hence a fresh random value.
///
/// The bytes are acquired at the registered `boundary.os_entropy` site in
/// [`crate::audit_sink`]; this type owns what they mean. The only production producer is
/// [`RunId::draw`], so no value of this type was chosen by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RunId([u8; 16]);

impl RunId {
    /// A fresh run. `None` when the OS CSPRNG fails, which opens no run.
    pub(super) fn draw() -> Option<Self> {
        crate::audit_sink::draw_run_entropy().map(RunId)
    }

    /// The sixteen bytes, for the canonical encoding.
    pub(super) fn bytes(&self) -> [u8; 16] {
        self.0
    }

    /// A fixed run, for tests of lines and encodings that name one.
    ///
    /// A test-only producer: it reuses a run on purpose, which is the hazard
    /// [`super::EventBinding::recurrence_of`] exists to report.
    #[cfg(test)]
    pub(crate) const fn fixed(bytes: [u8; 16]) -> Self {
        RunId(bytes)
    }
}

impl std::fmt::Display for RunId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_renders_as_32_hex_digits() {
        let rendered = RunId::draw()
            .expect("the OS CSPRNG yields a run")
            .to_string();
        assert_eq!(rendered.len(), 32, "{rendered}");
        assert!(
            rendered.chars().all(|c| c.is_ascii_hexdigit()),
            "{rendered}"
        );
        assert_eq!(
            RunId::fixed([0xab; 16]).to_string(),
            "abababababababababababababababab"
        );
    }
}
