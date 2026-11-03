//! Unit tests for keygate-multisig. Run with `cargo test -p keygate-multisig`.
//!
//! A throwaway `Recorder` contract stands in for the guarded target so the
//! relayed call and its side effect are both observable. The tests at the
//! bottom go one step further: they make the multisig the admin of a real
//! `keygate-core` registry, so the documented setup (route admin actions
//! through the multisig, never a single key) is covered end to end.
//!
//! Mocked auths are still recorded, so the `*_requires_*` tests at the bottom
//! assert on `env.auths()` to pin down which owner has to sign and for what.

// The crate is `no_std`, but the test harness is not, and `env.auths()` hands
// back a `std::vec::Vec`.
extern crate std;

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation, Ledger as _},
    Address, Env, IntoVal, String, Symbol, Val, Vec,
};

use keygate_core::{KeygateCore, KeygateCoreClient};

use super::{Error, KeygateMultisig, KeygateMultisigClient};

#[contracttype]
#[derive(Clone)]
enum RecKey {
    Last,
    Count,
}

/// Minimal target: stores the last value it was called with.
#[contract]
pub struct Recorder;

#[contractimpl]
impl Recorder {
    pub fn record(env: Env, value: i128) {
        let count: u32 = env.storage().persistent().get(&RecKey::Count).unwrap_or(0);
        env.storage().persistent().set(&RecKey::Last, &value);
        env.storage().persistent().set(&RecKey::Count, &(count + 1));
    }

    pub fn last(env: Env) -> Option<i128> {
        env.storage().persistent().get(&RecKey::Last)
    }

    pub fn count(env: Env) -> u32 {
        let count: Option<u32> = env.storage().persistent().get(&RecKey::Count);
        count.unwrap_or(0)
    }
}

/// Minimal target for a `Deny`-style call with no arguments.
#[contract]
pub struct Named;

#[contractimpl]
impl Named {
    pub fn tag(env: Env, label: String) {
        env.storage()
            .persistent()
            .set(&symbol_short!("label"), &label);
    }
}

struct Fixture {
    env: Env,
    multisig: Address,
    recorder: Address,
    owners: Vec<Address>,
    a: Address,
    b: Address,
    c: Address,
    outsider: Address,
}

impl Fixture {
    /// Deploys an n-of-3 multisig against a fresh `Recorder`.
    fn new(threshold: u32) -> Fixture {
        let env = Env::default();
        env.ledger().set_timestamp(1_000);
        let recorder = env.register(Recorder, ());
        let multisig = env.register(KeygateMultisig, ());
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        let c = Address::generate(&env);
        let outsider = Address::generate(&env);
        let mut owners = Vec::new(&env);
        owners.push_back(a.clone());
        owners.push_back(b.clone());
        owners.push_back(c.clone());
        env.mock_all_auths();
        KeygateMultisigClient::new(&env, &multisig).initialize(&owners, &threshold);
        Fixture {
            env,
            multisig,
            recorder,
            owners,
            a,
            b,
            c,
            outsider,
        }
    }

    fn client(&self) -> KeygateMultisigClient<'_> {
        KeygateMultisigClient::new(&self.env, &self.multisig)
    }

    fn recorder(&self) -> RecorderClient<'_> {
        RecorderClient::new(&self.env, &self.recorder)
    }

    /// A proposal calling `record(42)`.
    fn record_args(&self, value: i128) -> Vec<Val> {
        let mut args = Vec::new(&self.env);
        args.push_back(value.into_val(&self.env));
        args
    }

    fn submit_record(&self, caller: &Address, value: i128) -> u64 {
        self.client().submit(
            caller,
            &self.recorder,
            &symbol_short!("record"),
            &self.record_args(value),
        )
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
fn initialize_stores_owners_and_threshold() {
    let f = Fixture::new(2);
    assert_eq!(f.client().threshold(), 2);
    assert_eq!(f.client().owners(), f.owners);
    assert!(f.client().is_owner(&f.a));
    assert!(!f.client().is_owner(&f.outsider));
}

#[test]
fn initialize_rejects_bad_owner_sets() {
    let env = Env::default();
    let multisig = env.register(KeygateMultisig, ());
    let client = KeygateMultisigClient::new(&env, &multisig);
    env.mock_all_auths();

    let empty: Vec<Address> = Vec::new(&env);
    assert_eq!(
        client.try_initialize(&empty, &1),
        Err(Ok(Error::EmptyOwners))
    );

    let one = Address::generate(&env);
    let mut owners = Vec::new(&env);
    owners.push_back(one.clone());
    assert_eq!(
        client.try_initialize(&owners, &0),
        Err(Ok(Error::InvalidThreshold))
    );
    assert_eq!(
        client.try_initialize(&owners, &2),
        Err(Ok(Error::InvalidThreshold))
    );

    assert_eq!(client.try_initialize(&owners, &1), Ok(Ok(())));
    assert_eq!(
        client.try_initialize(&owners, &1),
        Err(Ok(Error::AlreadyInitialized))
    );
}

#[test]
fn initialize_rejects_duplicate_owners() {
    let env = Env::default();
    let multisig = env.register(KeygateMultisig, ());
    let client = KeygateMultisigClient::new(&env, &multisig);
    env.mock_all_auths();

    let a = Address::generate(&env);
    let mut owners = Vec::new(&env);
    owners.push_back(a.clone());
    owners.push_back(a);
    assert_eq!(
        client.try_initialize(&owners, &2),
        Err(Ok(Error::DuplicateOwner))
    );
}

#[test]
fn submit_auto_approves_for_the_proposer() {
    let f = Fixture::new(2);
    let id = f.submit_record(&f.a, 42);
    assert_eq!(id, 1);

    let proposal = f.client().proposal(&id).unwrap();
    assert_eq!(proposal.target, f.recorder);
    assert!(!proposal.executed);
    assert_eq!(proposal.approvals.len(), 1);
    assert_eq!(f.client().live_ids().len(), 1);
    // Nothing has run yet.
    assert_eq!(f.recorder().count(), 0);
}

#[test]
fn execute_waits_for_quorum_then_relays_the_call() {
    let f = Fixture::new(2);
    let id = f.submit_record(&f.a, 42);

    assert_eq!(
        f.client().try_execute(&f.a, &id),
        Err(Ok(Error::QuorumNotMet))
    );
    assert_eq!(f.recorder().count(), 0);

    assert_eq!(f.client().approve(&f.b, &id), 2);
    f.client().execute(&f.a, &id);

    assert_eq!(f.recorder().last(), Some(42));
    assert_eq!(f.recorder().count(), 1);
    assert!(f.client().proposal(&id).unwrap().executed);
    // Executed work leaves the pending set for the indexer's cursor.
    assert_eq!(f.client().live_ids().len(), 0);
}

#[test]
fn a_third_approval_is_not_required() {
    let f = Fixture::new(2);
    let id = f.submit_record(&f.a, 7);
    f.client().approve(&f.b, &id);
    f.client().execute(&f.c, &id);
    assert_eq!(f.recorder().last(), Some(7));
}

#[test]
fn executing_twice_is_refused() {
    let f = Fixture::new(1);
    let id = f.submit_record(&f.a, 1);
    f.client().execute(&f.a, &id);

    assert_eq!(
        f.client().try_execute(&f.a, &id),
        Err(Ok(Error::AlreadyExecuted))
    );
    assert_eq!(f.recorder().count(), 1);
}

#[test]
fn approving_twice_is_refused() {
    let f = Fixture::new(2);
    let id = f.submit_record(&f.a, 1);
    assert_eq!(
        f.client().try_approve(&f.a, &id),
        Err(Ok(Error::DuplicateApproval))
    );
    assert_eq!(f.client().approve(&f.b, &id), 2);
}

#[test]
fn unapprove_withdraws_support_and_can_block_execution() {
    let f = Fixture::new(2);
    let id = f.submit_record(&f.a, 1);
    f.client().approve(&f.b, &id);

    assert_eq!(f.client().unapprove(&f.b, &id), 1);
    assert_eq!(
        f.client().try_execute(&f.a, &id),
        Err(Ok(Error::QuorumNotMet))
    );

    f.client().approve(&f.b, &id);
    f.client().execute(&f.a, &id);
    assert_eq!(f.recorder().count(), 1);
}

#[test]
fn unapprove_by_someone_who_never_approved_is_refused() {
    let f = Fixture::new(2);
    let id = f.submit_record(&f.a, 1);
    assert_eq!(
        f.client().try_unapprove(&f.b, &id),
        Err(Ok(Error::DuplicateApproval))
    );
}

#[test]
fn cancel_closes_an_open_proposal() {
    let f = Fixture::new(2);
    let id = f.submit_record(&f.a, 1);
    f.client().cancel(&f.a, &id);

    assert!(f.client().proposal(&id).is_none());
    assert_eq!(f.client().live_ids().len(), 0);
    assert_eq!(
        f.client().try_execute(&f.a, &id),
        Err(Ok(Error::ProposalNotFound))
    );
}

#[test]
fn cannot_cancel_a_proposal_that_already_ran() {
    let f = Fixture::new(1);
    let id = f.submit_record(&f.a, 1);
    f.client().execute(&f.a, &id);
    assert_eq!(
        f.client().try_cancel(&f.a, &id),
        Err(Ok(Error::AlreadyExecuted))
    );
}

#[test]
fn non_owners_cannot_touch_proposals() {
    let f = Fixture::new(2);
    let id = f.submit_record(&f.a, 1);
    let outsider_args = f.record_args(9);

    assert_eq!(
        f.client().try_submit(
            &f.outsider,
            &f.recorder,
            &symbol_short!("record"),
            &outsider_args
        ),
        Err(Ok(Error::NotAnOwner))
    );
    assert_eq!(
        f.client().try_approve(&f.outsider, &id),
        Err(Ok(Error::NotAnOwner))
    );
    assert_eq!(
        f.client().try_execute(&f.outsider, &id),
        Err(Ok(Error::NotAnOwner))
    );
    assert_eq!(f.recorder().count(), 0);
}

#[test]
fn unknown_proposal_ids_are_not_found() {
    let f = Fixture::new(2);
    assert!(f.client().proposal(&99).is_none());
    assert_eq!(f.client().approvals(&99).len(), 0);
    assert_eq!(
        f.client().try_approve(&f.a, &99),
        Err(Ok(Error::ProposalNotFound))
    );
}

#[test]
fn proposals_relay_arguments_of_several_types() {
    let f = Fixture::new(1);
    let named = f.env.register(Named, ());
    let label = String::from_str(&f.env, "cold-storage");

    let mut args = Vec::new(&f.env);
    args.push_back(label.clone().into_val(&f.env));
    let id = f
        .client()
        .submit(&f.a, &named, &symbol_short!("tag"), &args);
    f.client().execute(&f.a, &id);

    // The recorder was never involved, so its counter proves the relay targeted
    // `named` and deserialised the String argument correctly.
    assert_eq!(f.recorder().count(), 0);
    assert_eq!(f.client().proposal(&id).unwrap().func, symbol_short!("tag"));
}

#[test]
fn owner_set_can_be_rotated_through_a_quorum_proposal() {
    let f = Fixture::new(2);
    let next_owners = {
        let mut list = Vec::new(&f.env);
        list.push_back(f.b.clone());
        list.push_back(f.c.clone());
        list
    };

    let mut args = Vec::new(&f.env);
    args.push_back(next_owners.clone().into_val(&f.env));
    args.push_back(2u32.into_val(&f.env));
    let id = f
        .client()
        .submit(&f.a, &f.multisig, &Symbol::new(&f.env, "set_owners"), &args);
    f.client().approve(&f.c, &id);
    f.client().execute(&f.a, &id);

    assert_eq!(f.client().owners().len(), 2);
    assert_eq!(f.client().threshold(), 2);
    assert!(!f.client().is_owner(&f.a));
    assert!(f.client().is_owner(&f.b));

    // The removed owner can no longer propose; the new ones can.
    let stale_args = f.record_args(3);
    assert_eq!(
        f.client()
            .try_submit(&f.a, &f.recorder, &symbol_short!("record"), &stale_args),
        Err(Ok(Error::NotAnOwner))
    );
    let follow_up = f.submit_record(&f.b, 3);
    assert_eq!(f.client().proposal(&follow_up).unwrap().approvals.len(), 1);
}

#[test]
fn a_rejected_rotation_leaves_owners_intact() {
    let f = Fixture::new(2);
    let empty: Vec<Address> = Vec::new(&f.env);
    let mut args = Vec::new(&f.env);
    args.push_back(empty.into_val(&f.env));
    args.push_back(1u32.into_val(&f.env));

    let id = f
        .client()
        .submit(&f.a, &f.multisig, &Symbol::new(&f.env, "set_owners"), &args);
    f.client().approve(&f.b, &id);
    // The rotation itself is refused, so `execute` must surface that rather
    // than mark the proposal done.
    assert!(f.client().try_execute(&f.a, &id).is_err());
    assert_eq!(f.client().owners().len(), 3);
    assert!(!f.client().proposal(&id).unwrap().executed);
}

#[test]
fn a_self_proposal_must_ask_for_something_the_multisig_can_apply() {
    let f = Fixture::new(2);

    // Anything other than the owner rotation is refused rather than relayed:
    // the contract cannot call itself, and pretending otherwise would let a
    // proposal look approvable when it can only ever fail.
    let id = f.client().submit(
        &f.a,
        &f.multisig,
        &symbol_short!("record"),
        &f.record_args(1),
    );
    f.client().approve(&f.b, &id);
    assert_eq!(
        f.client().try_execute(&f.a, &id),
        Err(Ok(Error::UnknownSelfCall))
    );
    assert!(!f.client().proposal(&id).unwrap().executed);

    // Right name, wrong shape. The arguments of a self-call are decoded by
    // hand, so they have to be exactly the two the rotation expects.
    let mut half = Vec::new(&f.env);
    half.push_back(f.record_args(7).get(0).unwrap());
    let bad = f
        .client()
        .submit(&f.a, &f.multisig, &Symbol::new(&f.env, "set_owners"), &half);
    f.client().approve(&f.b, &bad);
    assert_eq!(
        f.client().try_execute(&f.a, &bad),
        Err(Ok(Error::MalformedSelfCall))
    );
}

// --- relaying admin calls into a real registry -----------------------------
//
// The README's recommended deployment gives the multisig's contract address the
// admin role and keeps every owner's key out of it. These tests deploy the real
// `keygate-core` behind that arrangement, so `execute` is making an actual
// cross-contract call and the registry's own `require_auth` decides whether it
// lands. Nothing is stubbed: if the multisig were not the registry's admin, the
// paused flag and the issued grant below would not change.

/// A real registry administered by an n-of-3 multisig.
struct AdminFixture {
    env: Env,
    multisig: Address,
    core: Address,
    a: Address,
    b: Address,
    c: Address,
}

impl AdminFixture {
    fn new(threshold: u32) -> AdminFixture {
        let env = Env::default();
        env.ledger().set_timestamp(1_000);
        // The multisig has to exist before the registry is initialised, because
        // core records its admin at that point and never accepts a plain key.
        let multisig = env.register(KeygateMultisig, ());
        let core = env.register(KeygateCore, ());
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        let c = Address::generate(&env);
        let mut owners = Vec::new(&env);
        owners.push_back(a.clone());
        owners.push_back(b.clone());
        owners.push_back(c.clone());

        env.mock_all_auths();
        KeygateMultisigClient::new(&env, &multisig).initialize(&owners, &threshold);
        KeygateCoreClient::new(&env, &core).initialize(&multisig);

        AdminFixture {
            env,
            multisig,
            core,
            a,
            b,
            c,
        }
    }

    fn client(&self) -> KeygateMultisigClient<'_> {
        KeygateMultisigClient::new(&self.env, &self.multisig)
    }

    fn core_client(&self) -> KeygateCoreClient<'_> {
        KeygateCoreClient::new(&self.env, &self.core)
    }

    /// A proposal against the registry, with pre-encoded arguments so each test
    /// can reproduce exactly the call core exposes.
    fn submit(&self, caller: &Address, func: Symbol, args: Vec<Val>) -> u64 {
        self.client().submit(caller, &self.core, &func, &args)
    }
}

#[test]
fn pause_only_reaches_the_registry_at_quorum() {
    let f = AdminFixture::new(2);
    // No owner is the admin; the multisig's address is.
    assert_eq!(f.core_client().admin(), Some(f.multisig.clone()));

    let id = f.submit(&f.a, Symbol::new(&f.env, "pause"), Vec::new(&f.env));
    assert!(!f.core_client().paused());

    // The proposer alone is one short of the 2-of-3 threshold, so the relay must
    // not run and the registry must stay open.
    assert_eq!(
        f.client().try_execute(&f.a, &id),
        Err(Ok(Error::QuorumNotMet))
    );
    assert!(!f.core_client().paused());
    assert_eq!(f.client().live_ids().len(), 1);
    assert!(!f.client().proposal(&id).unwrap().executed);

    // A second approval is quorum; the third owner can push the button.
    f.client().approve(&f.b, &id);
    f.client().execute(&f.c, &id);

    assert!(f.core_client().paused());
    assert!(f.client().proposal(&id).unwrap().executed);
    // Executed work leaves the pending set, so an indexer's cursor drains.
    assert_eq!(f.client().live_ids().len(), 0);
}

#[test]
fn issue_through_a_quorum_proposal_creates_a_grant_that_checks() {
    let f = AdminFixture::new(2);
    let holder = Address::generate(&f.env);
    let resource = String::from_str(&f.env, "vault:main");
    let action = String::from_str(&f.env, "withdraw");

    let mut args = Vec::new(&f.env);
    args.push_back(resource.clone().into_val(&f.env));
    args.push_back(action.clone().into_val(&f.env));
    args.push_back(holder.clone().into_val(&f.env));
    args.push_back(3_600u64.into_val(&f.env));

    let id = f.submit(&f.a, Symbol::new(&f.env, "issue"), args);
    // Below quorum the holder has nothing: the registry was never called.
    assert!(!f.core_client().check(&resource, &action, &holder));
    assert_eq!(
        f.client().try_execute(&f.a, &id),
        Err(Ok(Error::QuorumNotMet))
    );
    assert!(!f.core_client().check(&resource, &action, &holder));

    f.client().approve(&f.b, &id);
    f.client().execute(&f.a, &id);

    // The grant is real registry state, so the capability check passes.
    assert!(f.core_client().check(&resource, &action, &holder));
    assert_eq!(f.core_client().live_ids().len(), 1);
    assert_eq!(f.client().live_ids().len(), 0);
}

#[test]
fn proposal_ids_are_monotonic_across_owners() {
    let f = Fixture::new(2);
    assert_eq!(f.submit_record(&f.a, 1), 1);
    assert_eq!(f.submit_record(&f.b, 2), 2);
    assert_eq!(f.submit_record(&f.c, 3), 3);
    assert_eq!(f.client().live_ids().len(), 3);
    assert_eq!(f.client().proposal(&2).unwrap().proposed_at, 1_000);
}

// --- who has to sign -------------------------------------------------------
//
// One test per entry point that calls `require_auth`, each asserting the exact
// authorisation the host recorded: address, contract function and arguments.
// The state-transition tests above cannot catch a dropped `require_auth`.
//
// `initialize` is the exception: it has no `require_auth` at all. The contract
// takes its owner set from deployment, so the first call is authorised by
// whoever deploys it, not by a signature the contract could check.

#[test]
fn submit_requires_the_owner() {
    let f = Fixture::new(2);

    f.submit_record(&f.a, 42);

    assert_signed_by(
        &f.env,
        &f.multisig,
        Symbol::new(&f.env, "submit"),
        (
            f.a.clone(),
            f.recorder.clone(),
            Symbol::new(&f.env, "record"),
            f.record_args(42),
        )
            .into_val(&f.env),
        &[&f.a],
    );
}

#[test]
fn approve_requires_the_approving_owner() {
    let f = Fixture::new(2);
    let id = f.submit_record(&f.a, 42);

    f.client().approve(&f.b, &id);

    // The proposer already approved at submission; this signature is `b`'s own.
    assert_signed_by(
        &f.env,
        &f.multisig,
        Symbol::new(&f.env, "approve"),
        (f.b.clone(), id).into_val(&f.env),
        &[&f.b],
    );
}

#[test]
fn unapprove_requires_the_approving_owner() {
    let f = Fixture::new(2);
    let id = f.submit_record(&f.a, 42);
    f.client().approve(&f.b, &id);

    f.client().unapprove(&f.b, &id);

    // Withdrawing consent must be the approver's own signature: an owner must
    // not be able to un-approve on someone else's behalf.
    assert_signed_by(
        &f.env,
        &f.multisig,
        Symbol::new(&f.env, "unapprove"),
        (f.b.clone(), id).into_val(&f.env),
        &[&f.b],
    );
}

#[test]
fn cancel_requires_the_owner() {
    let f = Fixture::new(2);
    let id = f.submit_record(&f.a, 42);

    f.client().cancel(&f.b, &id);

    assert_signed_by(
        &f.env,
        &f.multisig,
        Symbol::new(&f.env, "cancel"),
        (f.b.clone(), id).into_val(&f.env),
        &[&f.b],
    );
}

#[test]
fn execute_requires_the_owner() {
    let f = Fixture::new(1);
    let id = f.submit_record(&f.a, 42);

    f.client().execute(&f.b, &id);

    // The relayed call is authorised by the multisig's address, not by `b`, so
    // the only signature recorded at this level is the executing owner's.
    assert_signed_by(
        &f.env,
        &f.multisig,
        Symbol::new(&f.env, "execute"),
        (f.b.clone(), id).into_val(&f.env),
        &[&f.b],
    );
}
