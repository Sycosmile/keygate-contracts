//! Unit tests for keygate-policy. Run with `cargo test -p keygate-policy`.
//!
//! These tests deploy the real keygate-core registry so the cross-contract
//! capability check is covered rather than mocked away.
//!
//! Mocked auths are still recorded, so the `*_requires_*` tests at the bottom
//! assert on `env.auths()` to pin down who has to sign and for what.

// The crate is `no_std`, but the test harness is not, and `env.auths()` hands
// back a `std::vec::Vec`.
extern crate std;

use soroban_sdk::{
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation, Ledger as _},
    Address, Env, IntoVal, String, Symbol, Val, Vec,
};

use keygate_core::{KeygateCore, KeygateCoreClient};

use super::{Effect, Error, KeygatePolicy, KeygatePolicyClient, Rule};

const RESOURCE: &str = "vault:main";
const ACTION: &str = "withdraw";

struct Fixture {
    env: Env,
    policy: Address,
    registry: Address,
    admin: Address,
    holder: Address,
    other: Address,
}

impl Fixture {
    fn new(now: u64) -> Fixture {
        let env = Env::default();
        env.ledger().set_timestamp(now);

        let registry = env.register(KeygateCore, ());
        let policy = env.register(KeygatePolicy, ());
        let admin = Address::generate(&env);
        let holder = Address::generate(&env);
        let other = Address::generate(&env);
        env.mock_all_auths();

        KeygateCoreClient::new(&env, &registry).initialize(&admin);
        KeygatePolicyClient::new(&env, &policy).initialize(&admin, &registry);

        Fixture {
            env,
            policy,
            registry,
            admin,
            holder,
            other,
        }
    }

    fn policy_client(&self) -> KeygatePolicyClient<'_> {
        KeygatePolicyClient::new(&self.env, &self.policy)
    }

    fn registry_client(&self) -> KeygateCoreClient<'_> {
        KeygateCoreClient::new(&self.env, &self.registry)
    }

    fn resource(&self) -> String {
        String::from_str(&self.env, RESOURCE)
    }

    fn action(&self) -> String {
        String::from_str(&self.env, ACTION)
    }

    /// Grants the holder a live capability on the canonical triple.
    fn grant(&self) {
        self.registry_client()
            .issue(&self.resource(), &self.action(), &self.holder, &3_600);
    }

    fn evaluate(&self, holder: &Address) -> bool {
        self.policy_client()
            .evaluate(&self.resource(), &self.action(), holder)
    }
}

/// Asserts the last invocation required exactly `expected` to sign, in the
/// order the `require_auth` calls were made, and that each of them signed for
/// `func` on `contract` with `args`.
///
/// Signature checks belong to the host, so `env.auths()` is the only way a unit
/// test can see them. Asserting here is what turns a dropped `require_auth`
/// into a failing test rather than a silent widening of who may call in.
#[track_caller]
fn assert_signed_by(
    env: &Env,
    contract: &Address,
    func: Symbol,
    args: Vec<Val>,
    expected: &[&Address],
) {
    let mut want = std::vec::Vec::new();
    for &address in expected {
        want.push((
            address.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    contract.clone(),
                    func.clone(),
                    args.clone(),
                )),
                sub_invocations: std::vec::Vec::new(),
            },
        ));
    }
    assert_eq!(env.auths(), want);
}

#[test]
fn an_unconfigured_policy_denies_even_with_a_live_grant() {
    let f = Fixture::new(1_000);
    f.grant();

    // The registry says yes; the policy has not been told to allow anything.
    assert!(f
        .registry_client()
        .check(&f.resource(), &f.action(), &f.holder));
    assert!(!f.evaluate(&f.holder));
    assert_eq!(f.policy_client().default_effect(), Effect::Deny);
}

#[test]
fn an_allow_rule_defers_to_the_registry() {
    let f = Fixture::new(1_000);
    f.policy_client()
        .set_rule(&f.resource(), &f.action(), &Effect::Allow);

    // Allowed by policy but no capability yet.
    assert!(!f.evaluate(&f.holder));

    f.grant();
    assert!(f.evaluate(&f.holder));
    // Policy cannot invent a capability for someone who has none.
    assert!(!f.evaluate(&f.other));
}

#[test]
fn a_deny_rule_overrides_a_live_grant() {
    let f = Fixture::new(1_000);
    f.grant();
    f.policy_client()
        .set_rule(&f.resource(), &f.action(), &Effect::Allow);
    assert!(f.evaluate(&f.holder));

    f.policy_client()
        .set_rule(&f.resource(), &f.action(), &Effect::Deny);
    assert!(!f.evaluate(&f.holder));

    // Removing the rule restores registry-only behaviour.
    let removed = f.policy_client().remove_rule(&f.resource(), &f.action());
    assert_eq!(removed, 1);
    assert_eq!(f.policy_client().default_effect(), Effect::Deny);
    assert!(!f.evaluate(&f.holder));
}

#[test]
fn an_allow_default_effect_opens_everything_the_registry_allows() {
    let f = Fixture::new(1_000);
    f.grant();
    f.policy_client().set_default_effect(&Effect::Allow);
    assert!(f.evaluate(&f.holder));
    assert!(!f.evaluate(&f.other));
}

#[test]
fn deny_short_circuits_without_consulting_the_registry() {
    let f = Fixture::new(1_000);
    f.policy_client()
        .set_rule(&f.resource(), &f.action(), &Effect::Deny);
    // The registry is untouched, so there is nothing to prune and no read made.
    assert_eq!(f.registry_client().live_ids().len(), 0);
    assert!(!f.evaluate(&f.holder));
}

#[test]
fn set_rule_overwrites_in_place() {
    let f = Fixture::new(1_000);
    let first: Rule = f
        .policy_client()
        .set_rule(&f.resource(), &f.action(), &Effect::Allow);
    let second = f
        .policy_client()
        .set_rule(&f.resource(), &f.action(), &Effect::Deny);

    assert_eq!(first.id, second.id);
    assert_eq!(second.effect, Effect::Deny);
    assert_eq!(f.policy_client().rules().len(), 1);
}

#[test]
fn rules_are_listed_in_insertion_order() {
    let f = Fixture::new(1_000);
    let read = String::from_str(&f.env, "read");
    f.policy_client()
        .set_rule(&f.resource(), &read, &Effect::Allow);
    f.policy_client()
        .set_rule(&f.resource(), &f.action(), &Effect::Deny);

    let listed = f.policy_client().rules();
    assert_eq!(listed.len(), 2);
    // Insertion order is what the indexer replays, so ids must ascend.
    let first = listed.get(0).unwrap();
    let second = listed.get(1).unwrap();
    assert_eq!(first.id, 1);
    assert_eq!(second.id, 2);
    assert_eq!(first.effect, Effect::Allow);
    assert_eq!(second.effect, Effect::Deny);

    // The first rule was keyed on `read`, so the withdraw triple is still
    // covered only by the second one.
    assert!(!f.evaluate(&f.holder));
}

#[test]
fn empty_rule_names_are_rejected() {
    let f = Fixture::new(1_000);
    let empty = String::from_str(&f.env, "");
    let bad = f
        .policy_client()
        .try_set_rule(&empty, &f.action(), &Effect::Allow);
    // `set_rule` succeeds with the stored `Rule`, which carries no `PartialEq`,
    // so this matches the rejected arm instead of comparing the whole result.
    assert!(matches!(bad, Err(Ok(Error::EmptyName))));
}

#[test]
fn removing_an_absent_rule_fails() {
    let f = Fixture::new(1_000);
    let missing = f
        .policy_client()
        .try_remove_rule(&f.resource(), &f.action());
    assert_eq!(missing, Err(Ok(Error::RuleNotFound)));
}

#[test]
fn repointing_the_registry_changes_which_capabilities_count() {
    let f = Fixture::new(1_000);
    f.policy_client()
        .set_rule(&f.resource(), &f.action(), &Effect::Allow);

    let replacement = f.env.register(KeygateCore, ());
    let outsider = Address::generate(&f.env);
    KeygateCoreClient::new(&f.env, &replacement).initialize(&f.admin);
    KeygateCoreClient::new(&f.env, &replacement).issue(
        &f.resource(),
        &f.action(),
        &outsider,
        &3_600,
    );

    f.policy_client().set_registry(&replacement);
    assert_eq!(f.policy_client().registry(), Some(replacement.clone()));

    assert!(!f.evaluate(&f.holder));
    assert!(f.evaluate(&outsider));
}

#[test]
fn initialize_rejects_a_second_call() {
    let f = Fixture::new(1_000);
    let other = Address::generate(&f.env);
    let bad = f.policy_client().try_initialize(&other, &f.registry);
    assert_eq!(bad, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn admin_transfer_moves_control() {
    let f = Fixture::new(1_000);
    let successor = Address::generate(&f.env);

    assert_eq!(f.policy_client().admin(), Some(f.admin.clone()));
    f.policy_client().transfer_admin(&successor);
    assert_eq!(f.policy_client().admin(), Some(successor.clone()));

    // Everything the successor writes lands under the new admin, and rule
    // authoring keeps working from there.
    let rule = f
        .policy_client()
        .set_rule(&f.resource(), &f.action(), &Effect::Allow);
    assert_eq!(rule.id, 1);
}

// --- who has to sign -------------------------------------------------------
//
// One test per entry point that calls `require_auth`, each asserting the exact
// authorisation the host recorded: address, contract function and arguments.
// The state-transition tests above cannot catch a dropped `require_auth`.

#[test]
fn initialize_requires_the_admin() {
    let env = Env::default();
    let registry = env.register(KeygateCore, ());
    let policy = env.register(KeygatePolicy, ());
    let admin = Address::generate(&env);
    env.mock_all_auths();

    KeygatePolicyClient::new(&env, &policy).initialize(&admin, &registry);

    assert_signed_by(
        &env,
        &policy,
        Symbol::new(&env, "initialize"),
        (admin.clone(), registry.clone()).into_val(&env),
        &[&admin],
    );
}

#[test]
fn set_rule_requires_the_admin() {
    let f = Fixture::new(1_000);

    f.policy_client()
        .set_rule(&f.resource(), &f.action(), &Effect::Allow);

    assert_signed_by(
        &f.env,
        &f.policy,
        Symbol::new(&f.env, "set_rule"),
        (f.resource(), f.action(), Effect::Allow).into_val(&f.env),
        &[&f.admin],
    );
}

#[test]
fn remove_rule_requires_the_admin() {
    let f = Fixture::new(1_000);
    f.policy_client()
        .set_rule(&f.resource(), &f.action(), &Effect::Allow);

    f.policy_client().remove_rule(&f.resource(), &f.action());

    assert_signed_by(
        &f.env,
        &f.policy,
        Symbol::new(&f.env, "remove_rule"),
        (f.resource(), f.action()).into_val(&f.env),
        &[&f.admin],
    );
}

#[test]
fn set_default_effect_requires_the_admin() {
    let f = Fixture::new(1_000);

    f.policy_client().set_default_effect(&Effect::Allow);

    // Opening the default is the broadest privilege change in this contract,
    // so the signature on it matters more than most.
    assert_signed_by(
        &f.env,
        &f.policy,
        Symbol::new(&f.env, "set_default_effect"),
        (Effect::Allow,).into_val(&f.env),
        &[&f.admin],
    );
}

#[test]
fn set_registry_requires_the_admin() {
    let f = Fixture::new(1_000);
    let replacement = f.env.register(KeygateCore, ());

    f.policy_client().set_registry(&replacement);

    assert_signed_by(
        &f.env,
        &f.policy,
        Symbol::new(&f.env, "set_registry"),
        (replacement.clone(),).into_val(&f.env),
        &[&f.admin],
    );
}

#[test]
fn transfer_admin_requires_both_the_old_and_the_new_admin() {
    let f = Fixture::new(1_000);
    let successor = Address::generate(&f.env);

    f.policy_client().transfer_admin(&successor);

    // Both signatures are on the same call: the outgoing admin releases control
    // and the incoming one accepts it, so neither key can move it alone.
    assert_signed_by(
        &f.env,
        &f.policy,
        Symbol::new(&f.env, "transfer_admin"),
        (successor.clone(),).into_val(&f.env),
        &[&f.admin, &successor],
    );
}
