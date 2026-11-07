// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]
//! The text readers the ownership rules measure with: which `ExchangeEvent` variants a call
//! names, which the machine declares, which route drives each, and where the refusal
//! terminal is entered.

use std::collections::BTreeSet;

const EVENT_PATH: &str = "ExchangeEvent::";

/// The text of the balanced argument list that opens at the start of `after`: everything up
/// to the `)` that closes the already-consumed `(`.
fn balanced_arguments(after: &str) -> &str {
    let mut depth = 1usize;
    for (offset, ch) in after.char_indices() {
        depth = match ch {
            '(' => depth + 1,
            ')' => depth - 1,
            _ => depth,
        };
        if depth == 0 {
            return &after[..offset];
        }
    }
    after
}

/// The identifier that opens `text`.
fn leading_identifier(text: &str) -> String {
    text.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// Every `ExchangeEvent::` variant named in `arguments`.
fn variants_named(arguments: &str) -> impl Iterator<Item = String> + '_ {
    arguments
        .match_indices(EVENT_PATH)
        .map(|(at, _)| leading_identifier(&arguments[at + EVENT_PATH.len()..]))
        .filter(|variant| !variant.is_empty())
}

/// Source text the ownership rules read.
#[derive(Clone, Copy)]
pub(super) struct Source<'a>(&'a str);

impl<'a> Source<'a> {
    pub(super) fn new(text: &'a str) -> Self {
        Self(text)
    }

    /// Every `ExchangeEvent::` variant named inside the balanced argument list of each
    /// `call`.
    ///
    /// Paren-matched rather than line-matched: rustfmt splits both forms across lines
    /// (`Established::new(\n    value,\n    ExchangeEvent::X,\n)`), and a line matcher would
    /// see neither the multi-line establishes nor the `advance(match class { .. })`
    /// terminal.
    pub(super) fn events_named_in(self, call: &str) -> BTreeSet<String> {
        self.0
            .match_indices(call)
            .flat_map(|(index, _)| {
                variants_named(balanced_arguments(&self.0[index + call.len()..]))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Every variant `ExchangeEvent` declares, from the production half of
    /// `exchange_state.rs`.
    pub(super) fn declared_events(self) -> BTreeSet<String> {
        let start = self
            .0
            .find("pub(crate) enum ExchangeEvent {")
            .expect("ExchangeEvent is declared in exchange_state.rs");
        let body = &self.0[start..];
        let body =
            &body[body.find('{').map_or(0, |b| b + 1)..body.find("\n}").unwrap_or(body.len())];
        body.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//") && !l.starts_with('#'))
            .filter_map(|l| l.strip_suffix(','))
            .filter(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_alphanumeric()))
            .map(str::to_owned)
            .collect()
    }

    /// The events `ServedSuccess::tail` drives by name: the publication route.
    pub(super) fn publication_tail(self) -> BTreeSet<String> {
        let start = self
            .0
            .find("fn tail(&self)")
            .expect("ServedSuccess::tail is declared in exchange_state.rs");
        let body = &self.0[start..];
        let body = &body[..body.find("\n    }\n").expect("tail closes")];
        body.match_indices("E::")
            .map(|(at, _)| {
                body[at + 3..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect::<String>()
            })
            .filter(|v| !v.is_empty())
            .collect()
    }

    /// The function enclosing byte `at`: the identifier after the nearest `fn `.
    fn enclosing_fn(self, at: usize) -> String {
        let before = &self.0[..at];
        let mut search = before.len();
        while let Some(fn_at) = before[..search].rfind("fn ") {
            if starts_a_word(before, fn_at) {
                return leading_identifier(&before[fn_at + 3..]);
            }
            search = fn_at;
        }
        String::from("<no function>")
    }

    /// The enclosing function of every site that enters the refusal terminal: a
    /// `.refuse()` call, a path to `ExchangeProgress::refuse`, or any naming of the
    /// `Refused` event, so a direct `advance(ExchangeEvent::Refused)` is an entry too.
    /// Sorted, with repeats, so a second entry in the same function is a second entry.
    pub(super) fn refusal_entries(self) -> Vec<String> {
        let mut sites: Vec<String> = [
            ".refuse()",
            "ExchangeProgress::refuse",
            "ExchangeEvent::Refused",
        ]
        .iter()
        .flat_map(|pattern| self.0.match_indices(pattern).map(|(at, _)| at))
        .map(|at| self.enclosing_fn(at))
        .collect();
        sites.sort();
        sites
    }
}

/// The names of the routes in `routes` that carry `event`.
fn routes_carrying<'a>(event: &str, routes: &[(&'a str, &BTreeSet<String>)]) -> Vec<&'a str> {
    routes
        .iter()
        .filter(|(_, set)| set.contains(event))
        .map(|(name, _)| *name)
        .collect()
}

/// Each declared event that does not reach the machine by exactly one named route, and each
/// route naming an event the machine does not declare.
pub(super) fn route_defects(
    declared: &BTreeSet<String>,
    routes: &[(&str, &BTreeSet<String>)],
) -> Vec<String> {
    let misrouted = declared.iter().filter_map(|event| {
        let on = routes_carrying(event, routes);
        (on.len() != 1).then(|| format!("{event} reaches the machine by {on:?}"))
    });
    let unknown = routes.iter().flat_map(|(name, set)| {
        set.difference(declared)
            .map(move |unknown| format!("route {name} names {unknown}, which ExchangeEvent lacks"))
    });
    misrouted.chain(unknown).collect()
}

/// Whether the byte before `fn_at` leaves `fn ` standing as a whole word.
fn starts_a_word(before: &str, fn_at: usize) -> bool {
    fn_at == 0
        || !before[..fn_at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}
