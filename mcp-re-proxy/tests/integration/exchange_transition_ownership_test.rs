// SPDX-License-Identifier: Apache-2.0
//! A stage's transition is the stage's. The assembly may not state one.
//!
//! ADR-MCPRE-057 §4 puts the exchange lifecycle in a value, and
//! `ExchangeProgress::advance` owns transition LEGALITY: `(state, event)` is checked on
//! every advance of every build, and a refused step latches an anomaly that degrades the
//! exchange's retry claim to full strength. That is not the whole invariant.
//!
//! What it does not own is the correspondence between *the work happened* and *the event
//! was emitted*. `handle` used to run a stage and then state its event on the next line —
//! twenty such statements, in the one function where every refusal's retry contract is
//! decided. Apply the R-SEAL operational test: delete one and the machine is silently
//! behind the code until some later advance happens to be illegal. A check that can be
//! deleted is a check being remembered, not owned.
//!
//! `Established<T>` closes it. A stage that succeeds returns the event it justifies, and
//! `ExchangeProgress::establish` is the only way to take its value — so the assembly cannot reach
//! a stage's value without the machine learning the stage ran, and there is no `advance`
//! call left at the call site to forget.
//!
//! # What this test pins, and why it is a source scan
//!
//! The seal itself is the type, and the compiler enforces it. What the compiler cannot say
//! is that nobody has ADDED an `advance` back alongside a stage — which is the form the
//! regression takes, because it compiles and the relation accepts it (the event is legal
//! from that state; it was just already emitted).
//!
//! So the decidable property is disjointness:
//!
//! > No event established by a stage is also named by an `advance` in the serving path.
//!
//! and, so the list stays a measurement rather than a memory, the assembly's own events are
//! inventoried with the reason each one is the ASSEMBLY's fact and not some stage's.

use std::collections::BTreeSet;

mod event_scan;
mod source_tree;

use event_scan::{route_defects, Source};
use source_tree::{
    crate_source_outside_the_machine, production_half, production_of, serving_source,
};

/// The transitions the assembly states itself, and why each is the assembly's fact.
///
/// A stage establishes what its own work justifies. These are not any stage's: they are
/// established by the shape of the pipeline around the stages, so there is no function
/// whose success could carry them. "The assembly" is `handle` together with its region
/// functions — the code that COMPOSES stages rather than performing one.
///
/// A transition leaves this list when a stage or an owner takes it; see
/// [`RELOCATED_TO_THE_OWNER`] for the three that did.
const ASSEMBLY_OWNED: &[(&str, &str)] = &[
    (
        "ContinuationRetired",
        "decided by the answering-commitment region from a `Retirement`, not by the \
         outcomes do not proceed, and which of them spends a human's approval is a fact \
         about the exchange rather than about the call",
    ),
    (
        "BackendDispatched",
        "emitted at the handoff and BEFORE the await, so a cancelled or panicking dispatch \
         cannot leave the exchange claiming nothing happened. A value returned by the \
         dispatch could only be built after it returned, which is the wrong side of the \
         threshold",
    ),
    (
        "ContinuationNotRequired",
        "the absence of an obligation. No work establishes it — it is what the classifier \
         NOT having opened a leg means, and the arm that states it calls nothing",
    ),
];

/// Transitions this list used to hold, and the owner that took them.
///
/// `EvidenceRetained`, `TerminalResponseServed` and `OpenLegResponseServed` were the
/// assembly's own until the cross-machine invariants became an ENFORCEMENT: a success the
/// exchange machine cannot vouch for is now refused rather than asserted about, and the
/// decision has to be taken before retention and the `response.signed` record publish the
/// claim. So the three moved together into `ServedSuccess::tail()`, where the sequence is
/// written once and read twice — once to decide whether the success may be published, once
/// to publish it. Two lists at two call sites would have been the same remembered
/// correspondence `Established<T>` exists to remove.
///
/// They left this inventory for the reason the `stale` assertion exists: the list measures
/// what the serving path advances, and the serving path no longer advances them.
const RELOCATED_TO_THE_OWNER: &[&str] = &[
    "EvidenceRetained",
    "TerminalResponseServed",
    "OpenLegResponseServed",
];

/// The one event that is no stage's, the assembly's or the publication's: the refusal terminal.
///
/// `Refused` states no work, so no `Established` carries it and it is not an assembly-owned
/// advance: it is entered by `ExchangeProgress::refuse`, which the serving path calls in
/// exactly one function, [`REFUSAL_ENTRY`], the one every refusal's wire disposition is
/// derived through. Which terminal it reaches is the relation's answer, not the caller's.
const REFUSAL: &str = "Refused";

/// The one serving-path function that enters the refusal terminal.
const REFUSAL_ENTRY: &str = "disposition";

/// A stage's event is never also stated by the assembly.
#[test]
fn no_transition_a_stage_establishes_is_also_advanced_by_the_serving_path() {
    let production = serving_source();
    let production = production.as_str();
    let by_stages = Source::new(production).events_named_in("Established::new(");
    let by_assembly = Source::new(production).events_named_in(".advance(");

    assert!(
        !by_stages.is_empty(),
        "no stage declares an event — the matcher has stopped matching, and the assertion \
         below would pass on any source at all"
    );

    let both: Vec<&String> = by_stages.intersection(&by_assembly).collect();
    assert!(
        both.is_empty(),
        "{both:?} is established by a stage AND advanced by the serving path. The stage \
         already tells the machine it ran; the extra advance is the remembered statement \
         `Established` exists to remove. Delete the advance, not the stage's event."
    );
}

/// The assembly states exactly the transitions that are its own, and no others.
#[test]
fn the_serving_path_states_only_the_assembly_s_own_transitions() {
    let declared: BTreeSet<String> = ASSEMBLY_OWNED.iter().map(|(e, _)| e.to_string()).collect();
    let actual = Source::new(&serving_source()).events_named_in(".advance(");

    let undeclared: Vec<&String> = actual.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "the serving path advances {undeclared:?} itself. Before adding to ASSEMBLY_OWNED, \
         ask which function's SUCCESS establishes this fact — if one does, the event \
         belongs in its `Established`, where it cannot be forgotten."
    );

    let stale: Vec<&String> = declared.difference(&actual).collect();
    assert!(
        stale.is_empty(),
        "ASSEMBLY_OWNED names {stale:?}, which the serving path no longer advances. An event \
         that found a stage should leave this list, so the list stays a measurement."
    );
}

/// The relocated terminals stay relocated.
///
/// The three events below are the ones a success claim is published by, and the enforcement
/// that refuses an incoherent one works by driving them from a single tail inside the owner.
/// An `advance` for any of them reappearing in the serving path would be a second way to
/// reach a success terminal — one the publication decision does not guard — so the absence
/// is asserted rather than left to the inventory's prose.
#[test]
fn no_terminal_the_owner_publishes_is_advanced_by_the_serving_path_again() {
    let advanced = Source::new(&serving_source()).events_named_in(".advance(");
    let back: Vec<&&str> = RELOCATED_TO_THE_OWNER
        .iter()
        .filter(|e| advanced.contains(**e))
        .collect();
    assert!(
        back.is_empty(),
        "{back:?} is advanced by the serving path again. A success terminal reached outside          `ServedSuccess::tail()` is one the publication decision never saw."
    );
}

/// The 202's terminal fact is its stage's, not a publication-tail constant.
///
/// The bodyless 202 says the inner plane RECEIVED the message, so its terminal event travels
/// in the carrier the inner plane's observation mints on the arms that say so, and the
/// publication that enters the terminal reads that carrier's event. Were it driven from a
/// fixed tail instead, the 202 terminal would rest on the observation being called first —
/// an order the compiler does not hold.
#[test]
fn the_202_terminal_is_entered_through_its_stage_s_carrier() {
    let by_stages = Source::new(&serving_source()).events_named_in("Established::new(");
    assert!(
        by_stages.contains("NotificationAcknowledged"),
        "no stage establishes `NotificationAcknowledged`: the 202 terminal no longer requires \
         the inner plane's observation that the message arrived. Stages establish {by_stages:?}"
    );
}

/// Every event the machine declares reaches it by exactly one route.
///
/// The routes are four: a stage's `Established`, the assembly's own `advance`, the
/// publication tail `PublishPermit::publish` drives, and the refusal terminal. An event on
/// none of them is an event no measured route accounts for; an event on two is a fact stated
/// twice. The publication route is read from `ServedSuccess::tail` itself, so the relocated
/// list cannot drift from what the permit actually drives.
#[test]
fn every_exchange_event_reaches_the_machine_by_exactly_one_route() {
    let machine = production_of("exchange_state.rs");
    let declared = Source::new(&machine).declared_events();
    assert!(
        declared.len() > 10 && declared.contains(REFUSAL),
        "the enum reader has stopped reading ExchangeEvent: {declared:?}"
    );
    let stage = Source::new(&serving_source()).events_named_in("Established::new(");
    let assembly: BTreeSet<String> = ASSEMBLY_OWNED.iter().map(|(e, _)| e.to_string()).collect();
    let tail = Source::new(&machine).publication_tail();
    let relocated: BTreeSet<String> = RELOCATED_TO_THE_OWNER
        .iter()
        .map(|e| e.to_string())
        .collect();
    assert_eq!(
        tail, relocated,
        "ServedSuccess::tail drives {tail:?}, and RELOCATED_TO_THE_OWNER names {relocated:?}"
    );
    let refusal = BTreeSet::from([REFUSAL.to_owned()]);
    let defects = route_defects(
        &declared,
        &[
            ("stage", &stage),
            ("assembly", &assembly),
            ("publication", &tail),
            ("refusal", &refusal),
        ],
    );
    assert!(defects.is_empty(), "{defects:#?}");
}

/// The refusal terminal is entered only by `ExchangeProgress::refuse`, and only from the
/// function that derives a refusal's wire disposition.
///
/// `refuse` is the one production advance of `Refused`; outside the machine the crate
/// enters it at exactly one site, in [`REFUSAL_ENTRY`]. A second `refuse()` — or an
/// `advance(ExchangeEvent::Refused)` — anywhere in the crate is a refusal entered without the
/// disposition the client is told, and fails here.
#[test]
fn the_refusal_terminal_is_entered_only_by_refuse_from_the_disposition() {
    assert_eq!(
        Source::new(&crate_source_outside_the_machine()).refusal_entries(),
        vec![REFUSAL_ENTRY.to_owned()],
        "the crate enters the refusal terminal outside `{REFUSAL_ENTRY}`, or no longer from it"
    );
    let publication = production_of("exchange_state/publication.rs");
    assert_eq!(
        Source::new(&publication).events_named_in(".advance("),
        BTreeSet::from([REFUSAL.to_owned()]),
        "publication.rs advances a named event other than the refusal"
    );
    assert_eq!(
        Source::new(&publication).refusal_entries(),
        vec!["refuse".to_owned()]
    );
    assert!(
        !Source::new(&production_of("exchange_state.rs"))
            .events_named_in(".advance(")
            .contains(REFUSAL),
        "exchange_state.rs advances `Refused` by name beside `refuse`"
    );
}

/// The refusal and route rules detect what they claim to.
#[test]
fn the_refusal_rule_would_catch_an_unauthorized_entry() {
    let authorized = "fn disposition(p: &mut ExchangeProgress) {\n    p.refuse();\n}\n\
                      fn other(&self) { self.responses.refuse(observer, point, refusal, owed); }";
    assert_eq!(
        Source::new(authorized).refusal_entries(),
        vec![REFUSAL_ENTRY.to_owned()],
        "the authorized entry is seen, and the receipt's `refuse(..)` is not an entry"
    );
    for (case, unauthorized) in [
        (
            "a second refuse() call",
            "\nfn region(progress: &mut ExchangeProgress) {\n    progress.refuse();\n}",
        ),
        (
            "a path call",
            "\nfn region(p: &mut ExchangeProgress) { ExchangeProgress::refuse(p); }",
        ),
        (
            "a direct advance",
            "\nfn region(p: &mut ExchangeProgress) { p.advance(ExchangeEvent::Refused); }",
        ),
        (
            "a second entry in the disposition",
            "\nfn disposition(p: &mut ExchangeProgress) { p.refuse(); }",
        ),
    ] {
        let source = format!("{authorized}{unauthorized}");
        assert_ne!(
            Source::new(&source).refusal_entries(),
            vec![REFUSAL_ENTRY.to_owned()],
            "{case} was not detected"
        );
    }

    let set =
        |events: &[&str]| -> BTreeSet<String> { events.iter().map(|e| e.to_string()).collect() };
    let declared = set(&["A", "B", "Refused"]);
    assert!(route_defects(
        &declared,
        &[("x", &set(&["A", "B"])), ("refusal", &set(&["Refused"]))]
    )
    .is_empty());
    for (case, routes) in [
        (
            "an event on no route",
            vec![("x", set(&["A"])), ("refusal", set(&["Refused"]))],
        ),
        (
            "an event on two routes",
            vec![("x", set(&["A", "B"])), ("refusal", set(&["Refused", "B"]))],
        ),
        (
            "a route naming an undeclared event",
            vec![("x", set(&["A", "B", "C"])), ("refusal", set(&["Refused"]))],
        ),
    ] {
        let routes: Vec<(&str, &BTreeSet<String>)> = routes.iter().map(|(n, s)| (*n, s)).collect();
        assert!(
            !route_defects(&declared, &routes).is_empty(),
            "{case} was not detected"
        );
    }
    let enum_text =
        "pub(crate) enum ExchangeEvent {\n    /// doc\n    A,\n    #[allow(x)]\n    B,\n}\n";
    assert_eq!(Source::new(enum_text).declared_events(), set(&["A", "B"]));
}

/// The rule detects what it claims to.
///
/// Without this, a matcher that never matches leaves both assertions above vacuously true,
/// and a green run would mean nothing at all.
#[test]
fn the_rule_would_catch_a_reintroduced_advance() {
    let regressed = "fn f() { let v = Established::new(x, ExchangeEvent::ReplayAdmitted); \
                     progress.advance(ExchangeEvent::ReplayAdmitted); }";
    let by_stages = Source::new(regressed).events_named_in("Established::new(");
    let by_assembly = Source::new(regressed).events_named_in(".advance(");
    assert!(
        by_stages.contains("ReplayAdmitted") && by_assembly.contains("ReplayAdmitted"),
        "the matcher must see both halves of the regression"
    );

    let split = "fn f() {\n    progress.advance(match class {\n        A => \
                 ExchangeEvent::TerminalResponseServed,\n        B => \
                 ExchangeEvent::OpenLegResponseServed,\n    });\n}";
    let both = Source::new(split).events_named_in(".advance(");
    assert!(
        both.contains("TerminalResponseServed") && both.contains("OpenLegResponseServed"),
        "a multi-line advance names both of its events; a line matcher would see neither"
    );

    let fixture_only = production_half(
        "fn f() {}\n#[cfg(test)]\nmod tests { progress.advance(ExchangeEvent::ReplayAdmitted); }",
    );
    assert!(
        Source::new(&fixture_only)
            .events_named_in(".advance(")
            .is_empty(),
        "test code is out of scope, so a fixture cannot make the gate fail or pass"
    );
    // And the other direction: an advance reintroduced BELOW the test module is production
    // and must be seen. A truncating split reported a clean pass over every line after the
    // first `#[cfg(test)]`, which in this file is not the test module at all.
    let below_tests = production_half(
        "#[cfg(test)]\nmod tests {\n}\nfn late() { progress.advance(ExchangeEvent::ReplayAdmitted); }\n",
    );
    assert!(
        Source::new(&below_tests)
            .events_named_in(".advance(")
            .contains("ReplayAdmitted"),
        "an advance below the test module must still be seen"
    );
}

/// The carrier's other half: a stage's product cannot be read past the machine.
///
/// `Established<T>` is constructible anywhere in the crate, so what makes it a carrier
/// rather than a wrapper is that NOTHING yields its value but `ExchangeProgress::establish` — no
/// public field, no accessor, no `Deref`. Privacy is a compile-time fact, but a widened
/// field compiles too, and would leave every behavioural control green while the assembly
/// quietly read `.value` without advancing. Measured at the source, in the production half
/// of `exchange_state.rs`, reached from the serving anchor's parent directory.
#[test]
fn the_carrier_has_no_reader_but_establish() {
    let production = production_of("exchange_state.rs");

    let struct_at = production
        .find("struct Established<T> {")
        .expect("the carrier is declared in exchange_state.rs");
    let body_end = production[struct_at..]
        .find("\n}")
        .map(|end| struct_at + end)
        .expect("the carrier's declaration closes");
    let fields = &production[struct_at..body_end];
    assert!(
        !fields.contains("pub"),
        "a field of Established is readable outside the machine: {fields}"
    );
    assert!(
        production[..struct_at].contains("#[must_use"),
        "the carrier lost its #[must_use]: a dropped stage product would no longer warn"
    );

    let impl_at = production
        .find("impl<T> Established<T> {")
        .expect("the carrier has an inherent impl");
    let impl_end = production[impl_at..]
        .find("\n}")
        .map(|end| impl_at + end)
        .expect("the impl closes");
    let methods: Vec<&str> = production[impl_at..impl_end]
        .lines()
        .filter(|l| l.trim_start().starts_with("pub") && l.contains("fn "))
        .collect();
    assert_eq!(
        methods.len(),
        1,
        "Established must expose exactly one method, its constructor: {methods:?}"
    );
    assert!(methods[0].contains("fn new("), "{methods:?}");
    assert!(
        !production.contains("impl<T> std::ops::Deref for Established")
            && !production.contains("impl<T> Deref for Established")
            && !production.contains("for Established<T>"),
        "a trait impl on Established could open the carrier without the machine"
    );
}

/// The inventory is not a bare list: every entry states why the transition is the
/// assembly's rather than some stage's.
#[test]
fn every_assembly_owned_transition_states_why_no_stage_carries_it() {
    for (event, reason) in ASSEMBLY_OWNED {
        assert!(
            reason.len() > 40,
            "{event} has no real justification: {reason:?}"
        );
    }
}
