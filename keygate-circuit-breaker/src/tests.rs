//! Unit tests for keygate-circuit-breaker. Run with `cargo test -p keygate-circuit-breaker`.
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

use super::{Error, KeygateBreaker, KeygateBreakerClient, Outcome};

const RESOURCE: &str = "vault:main";
const WINDOW: u64 = 3_600;
const LIMIT: i128 = 1_000;

struct Fixture {
    env: Env,
    contract: Address,
    admin: Address,
}

impl Fixture {
    /// Deploys a breaker with `vault:main` limited to 1000 per hour.
    fn new(now: u64) -> Fixture {
        let env = Env::default();
        env.ledger().set_timestamp(now);
        let contract = env.register(KeygateBreaker, ());
        let admin = Address::generate(&env);
        env.mock_all_auths();
        let client = KeygateBreakerClient::new(&env, &contract);
        client.initialize(&admin);
        client.configure(&String::from_str(&env, RESOURCE), &LIMIT, &WINDOW);
        Fixture {
            env,
            contract,
            admin,
        }
    }

    fn client(&self) -> KeygateBreakerClient<'_> {
        KeygateBreakerClient::new(&self.env, &self.contract)
    }

    fn resource(&self) -> String {
        String::from_str(&self.env, RESOURCE)
    }

    fn advance(&self, seconds: u64) {
        let now = self.env.ledger().timestamp();
        self.env.ledger().set_timestamp(now + seconds);
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
fn charges_reduce_the_remaining_budget() {
    let f = Fixture::new(1_000);
    assert_eq!(f.client().enforce(&f.resource(), &400), Outcome::Charged);
    assert_eq!(f.client().remaining(&f.resource()), 600);

    f.client().enforce(&f.resource(), &250);
    assert_eq!(f.client().remaining(&f.resource()), 350);

    let state = f.client().state(&f.resource()).unwrap();
    assert_eq!(state.used, 650);
    assert!(!state.tripped);
}

#[test]
fn spending_exactly_the_limit_is_allowed() {
    let f = Fixture::new(1_000);
    f.client().enforce(&f.resource(), &LIMIT);
    assert_eq!(f.client().remaining(&f.resource()), 0);
    assert!(!f.client().is_tripped(&f.resource()));
}

#[test]
fn crossing_the_limit_reports_breached_and_trips() {
    let f = Fixture::new(1_000);
    f.client().enforce(&f.resource(), &900);

    // The breaching call *succeeds*. A contract that returns an error has its
    // own writes discarded, so an error here would also discard the latch it
    // had just recorded — and a breaker that forgets it tripped is only a
    // comparison. The breach is a value the caller has to act on.
    assert_eq!(f.client().enforce(&f.resource(), &200), Outcome::Breached);
    assert!(f.client().is_tripped(&f.resource()));
    assert_eq!(f.client().remaining(&f.resource()), 0);

    // Once tripped, even a trivial amount is refused, and there the refusal can
    // be an error because there is nothing left to record. This is the point:
    // the resource stops bleeding instead of allowing the next small withdrawal.
    let after = f.client().try_enforce(&f.resource(), &1);
    assert_eq!(after, Err(Ok(Error::Tripped)));
}

#[test]
fn a_breach_is_recorded_with_the_offending_total() {
    let f = Fixture::new(1_000);
    f.client().enforce(&f.resource(), &900);
    f.client().enforce(&f.resource(), &200);

    let state = f.client().state(&f.resource()).unwrap();
    assert_eq!(state.used, 1_100);
    assert!(state.tripped);
}

#[test]
fn the_trip_survives_the_window_rolling_over() {
    let f = Fixture::new(1_000);
    f.client().enforce(&f.resource(), &2_000);
    f.advance(WINDOW + 1);

    // Time passing must not silently re-open a latched resource.
    let still = f.client().try_enforce(&f.resource(), &1);
    assert_eq!(still, Err(Ok(Error::Tripped)));
}

#[test]
fn an_untripped_window_resets_after_it_elapses() {
    let f = Fixture::new(1_000);
    f.client().enforce(&f.resource(), &900);
    assert_eq!(f.client().remaining(&f.resource()), 100);

    f.advance(WINDOW);
    assert_eq!(f.client().remaining(&f.resource()), LIMIT);
    f.client().enforce(&f.resource(), &900);
    assert_eq!(f.client().remaining(&f.resource()), 100);
}

#[test]
fn a_new_window_anchors_on_the_first_charge_after_expiry() {
    let f = Fixture::new(1_000);
    f.client().enforce(&f.resource(), &500);

    f.advance(WINDOW - 10);
    // Still inside the original window.
    assert_eq!(f.client().remaining(&f.resource()), 500);

    f.advance(20);
    assert_eq!(f.client().remaining(&f.resource()), LIMIT);
    // A view must not persist the roll, so storage still holds the old window.
    let stale = f.client().state(&f.resource()).unwrap();
    assert_eq!(stale.window_start, 1_000);
    assert_eq!(stale.used, 500);

    f.client().enforce(&f.resource(), &600);
    let rolled = f.client().state(&f.resource()).unwrap();
    assert_eq!(rolled.window_start, 4_610);
    assert_eq!(rolled.used, 600);
}

#[test]
fn reset_clears_the_latch_and_starts_a_fresh_window() {
    let f = Fixture::new(1_000);
    f.client().enforce(&f.resource(), &2_000);
    assert!(f.client().is_tripped(&f.resource()));

    f.client().reset(&f.resource());
    assert!(!f.client().is_tripped(&f.resource()));
    assert_eq!(f.client().remaining(&f.resource()), LIMIT);
    f.client().enforce(&f.resource(), &10);
}

#[test]
fn trip_closes_a_resource_before_any_breach() {
    let f = Fixture::new(1_000);
    f.client().trip(&f.resource());
    let blocked = f.client().try_enforce(&f.resource(), &1);
    assert_eq!(blocked, Err(Ok(Error::Tripped)));

    f.client().reset(&f.resource());
    f.client().enforce(&f.resource(), &1);
}

#[test]
fn non_positive_amounts_are_refused_without_charging() {
    let f = Fixture::new(1_000);
    assert_eq!(
        f.client().try_enforce(&f.resource(), &0),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(
        f.client().try_enforce(&f.resource(), &-5),
        Err(Ok(Error::InvalidAmount))
    );
    let state = f.client().state(&f.resource());
    assert!(state.is_none());
}

#[test]
fn an_unknown_resource_is_not_configured() {
    let f = Fixture::new(1_000);
    let other = String::from_str(&f.env, "vault:other");
    assert_eq!(
        f.client().try_enforce(&other, &1),
        Err(Ok(Error::NotConfigured))
    );
    assert!(f.client().config(&other).is_none());
    assert!(!f.client().is_tripped(&other));
}

#[test]
fn invalid_limits_and_windows_are_rejected() {
    let f = Fixture::new(1_000);
    // `configure` succeeds with a `Config`, which carries no `PartialEq`, so the
    // rejections are matched by arm rather than compared as whole values.
    assert!(matches!(
        f.client().try_configure(&f.resource(), &0, &WINDOW),
        Err(Ok(Error::InvalidLimit))
    ));
    assert!(matches!(
        f.client().try_configure(&f.resource(), &-1, &WINDOW),
        Err(Ok(Error::InvalidLimit))
    ));
    assert!(matches!(
        f.client().try_configure(&f.resource(), &LIMIT, &0),
        Err(Ok(Error::InvalidWindow))
    ));
    // The original configuration survived the rejected writes.
    let config = f.client().config(&f.resource()).unwrap();
    assert_eq!(config.limit, LIMIT);
    assert_eq!(config.window, WINDOW);
}

#[test]
fn reconfiguring_does_not_duplicate_the_resource_list() {
    let f = Fixture::new(1_000);
    f.client().configure(&f.resource(), &2_000, &WINDOW);
    assert_eq!(f.client().resources().len(), 1);

    let second = String::from_str(&f.env, "bridge:out");
    f.client().configure(&second, &500, &WINDOW);
    assert_eq!(f.client().resources().len(), 2);
}

#[test]
fn replacing_a_limit_does_not_forgive_a_trip() {
    let f = Fixture::new(1_000);
    f.client().enforce(&f.resource(), &2_000);

    f.client().configure(&f.resource(), &10_000, &WINDOW);
    let blocked = f.client().try_enforce(&f.resource(), &1);
    assert_eq!(blocked, Err(Ok(Error::Tripped)));
}

#[test]
fn initialize_rejects_a_second_call() {
    let f = Fixture::new(1_000);
    let stranger = Address::generate(&f.env);
    assert_eq!(
        f.client().try_initialize(&stranger),
        Err(Ok(Error::AlreadyInitialized))
    );
    assert_eq!(f.client().admin(), Some(f.admin.clone()));
}

// --- who has to sign -------------------------------------------------------
//
// One test per entry point that calls `require_auth`, each asserting the exact
// authorisation the host recorded: address, contract function and arguments.
// The state-transition tests above cannot catch a dropped `require_auth`.
//
// `enforce`, `remaining` and the views are deliberately unauthorised: the
// breaker is a budget guard for callers the registry has already authenticated.

#[test]
fn initialize_requires_the_admin() {
    let env = Env::default();
    let contract = env.register(KeygateBreaker, ());
    let admin = Address::generate(&env);
    env.mock_all_auths();

    KeygateBreakerClient::new(&env, &contract).initialize(&admin);

    assert_signed_by(
        &env,
        &contract,
        Symbol::new(&env, "initialize"),
        (admin.clone(),).into_val(&env),
        &[&admin],
    );
}

#[test]
fn configure_requires_the_admin() {
    let f = Fixture::new(1_000);

    f.client().configure(&f.resource(), &2_000, &WINDOW);

    assert_signed_by(
        &f.env,
        &f.contract,
        Symbol::new(&f.env, "configure"),
        (f.resource(), 2_000_i128, WINDOW).into_val(&f.env),
        &[&f.admin],
    );
}

#[test]
fn trip_requires_the_admin() {
    let f = Fixture::new(1_000);

    f.client().trip(&f.resource());

    assert_signed_by(
        &f.env,
        &f.contract,
        Symbol::new(&f.env, "trip"),
        (f.resource(),).into_val(&f.env),
        &[&f.admin],
    );
}

#[test]
fn reset_requires_the_admin() {
    let f = Fixture::new(1_000);
    f.client().trip(&f.resource());

    f.client().reset(&f.resource());

    // Re-opening a latched resource hands the budget back, so it is an admin
    // action even when the latch came from an automatic breach.
    assert_signed_by(
        &f.env,
        &f.contract,
        Symbol::new(&f.env, "reset"),
        (f.resource(),).into_val(&f.env),
        &[&f.admin],
    );
}
