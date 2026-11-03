//! keygate-multisig: threshold administration for the rest of keygate.
//!
//! The registry, policy and breaker all have a single admin address. That is
//! fine for a user-facing capability, but it means one key can freeze issuance,
//! flip a policy default to `Allow`, or repoint a policy at a hostile registry.
//! This contract puts those actions behind m-of-n approval by holding the admin
//! address itself: propose the call, gather approvals, execute it, and the
//! target sees the multisig as the caller.
//!
//! Proposals carry an already-encoded argument list (`Vec<Val>`), so the
//! multisig can relay any call without keygate needing to know every target's
//! signature at compile time.
//!
//! One relay is impossible: Soroban will not let a contract call back into
//! itself, so a proposal that targets this multisig cannot go through
//! `invoke_contract`. `execute` recognises those proposals and applies the one
//! self-administration call it knows (`set_owners`) inline instead, decoding
//! the arguments by hand. Anything else addressed to the multisig is refused
//! with `UnknownSelfCall` rather than guessed at.

#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env, Symbol,
    TryIntoVal, Val, Vec,
};

#[contracttype]
#[derive(Clone)]
pub struct Proposal {
    pub id: u64,
    pub target: Address,
    pub func: Symbol,
    pub args: Vec<Val>,
    /// Owners who have approved. The proposer is included at submission.
    pub approvals: Vec<Address>,
    pub executed: bool,
    pub proposed_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Owners,
    Threshold,
    NextId,
    LiveIds,
    Proposal(u64),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    EmptyOwners = 2,
    DuplicateOwner = 3,
    InvalidThreshold = 4,
    NotAnOwner = 5,
    ProposalNotFound = 6,
    AlreadyExecuted = 7,
    DuplicateApproval = 8,
    QuorumNotMet = 9,
    UnknownSelfCall = 10,
    MalformedSelfCall = 11,
}

#[contract]
pub struct KeygateMultisig;

#[contractimpl]
impl KeygateMultisig {
    /// `threshold` of `owners` must approve a proposal before it can execute.
    pub fn initialize(env: Env, owners: Vec<Address>, threshold: u32) -> Result<(), Error> {
        if env.storage().persistent().has(&DataKey::Owners) {
            return Err(Error::AlreadyInitialized);
        }
        if owners.is_empty() {
            return Err(Error::EmptyOwners);
        }
        if threshold == 0 || threshold > owners.len() {
            return Err(Error::InvalidThreshold);
        }
        let mut unique = Vec::new(&env);
        for owner in owners.iter() {
            if unique.contains(&owner) {
                return Err(Error::DuplicateOwner);
            }
            unique.push_back(owner);
        }
        env.storage().persistent().set(&DataKey::Owners, &unique);
        env.storage()
            .persistent()
            .set(&DataKey::Threshold, &threshold);
        env.events()
            .publish((symbol_short!("ms_init"),), (unique, threshold));
        Ok(())
    }

    /// Records a call to be made once quorum approves it.
    pub fn submit(
        env: Env,
        caller: Address,
        target: Address,
        func: Symbol,
        args: Vec<Val>,
    ) -> Result<u64, Error> {
        Self::require_owner(&env, &caller)?;
        let id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::NextId)
            .unwrap_or(1);
        env.storage().persistent().set(&DataKey::NextId, &(id + 1));

        let mut approvals = Vec::new(&env);
        approvals.push_back(caller.clone());
        let proposal = Proposal {
            id,
            target: target.clone(),
            func: func.clone(),
            args: args.clone(),
            approvals,
            executed: false,
            proposed_at: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);

        let mut ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::LiveIds)
            .unwrap_or(Vec::new(&env));
        ids.push_back(id);
        env.storage().persistent().set(&DataKey::LiveIds, &ids);

        env.events()
            .publish((symbol_short!("submitted"), caller), proposal);
        Ok(id)
    }

    /// Adds `caller` to the proposal's approvals.
    pub fn approve(env: Env, caller: Address, id: u64) -> Result<u32, Error> {
        Self::require_owner(&env, &caller)?;
        let mut proposal = Self::load(&env, id)?;
        if proposal.executed {
            return Err(Error::AlreadyExecuted);
        }
        if proposal.approvals.contains(&caller) {
            return Err(Error::DuplicateApproval);
        }
        proposal.approvals.push_back(caller.clone());
        let count = proposal.approvals.len();
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);
        env.events()
            .publish((symbol_short!("approved"), caller), id);
        Ok(count)
    }

    /// Withdraws `caller`'s approval, for when a proposal is revised or an
    /// owner approves by mistake.
    pub fn unapprove(env: Env, caller: Address, id: u64) -> Result<u32, Error> {
        Self::require_owner(&env, &caller)?;
        let mut proposal = Self::load(&env, id)?;
        if proposal.executed {
            return Err(Error::AlreadyExecuted);
        }
        if !proposal.approvals.contains(&caller) {
            return Err(Error::DuplicateApproval);
        }
        let mut kept = Vec::new(&env);
        for approver in proposal.approvals.iter() {
            if approver != caller {
                kept.push_back(approver);
            }
        }
        proposal.approvals = kept;
        let count = proposal.approvals.len();
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);
        env.events()
            .publish((symbol_short!("unapprove"), caller), id);
        Ok(count)
    }

    /// Drops a proposal that has not run.
    pub fn cancel(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        Self::require_owner(&env, &caller)?;
        let proposal = Self::load(&env, id)?;
        if proposal.executed {
            return Err(Error::AlreadyExecuted);
        }
        env.storage().persistent().remove(&DataKey::Proposal(id));
        let mut kept = Vec::new(&env);
        let ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::LiveIds)
            .unwrap_or(Vec::new(&env));
        for candidate in ids.iter() {
            if candidate != id {
                kept.push_back(candidate);
            }
        }
        env.storage().persistent().set(&DataKey::LiveIds, &kept);
        env.events()
            .publish((symbol_short!("cancelled"), caller), id);
        Ok(())
    }

    /// Makes the recorded call. The target authorises this by treating the
    /// multisig's own address as the caller, so keygate contracts should be
    /// administered through here rather than by handing a key to one person.
    pub fn execute(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        Self::require_owner(&env, &caller)?;
        let proposal = Self::load(&env, id)?;
        if proposal.executed {
            return Err(Error::AlreadyExecuted);
        }
        let threshold: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Threshold)
            .ok_or(Error::EmptyOwners)?;
        if proposal.approvals.len() < threshold {
            return Err(Error::QuorumNotMet);
        }

        // A proposal aimed at this contract cannot be relayed: Soroban refuses
        // to re-enter a contract, so the rotation is applied inline instead.
        if proposal.target == env.current_contract_address() {
            Self::run_on_self(&env, &proposal.func, &proposal.args)?;
        } else {
            // The return value is discarded rather than decoded as `()`: a
            // proposal is about the call's effect, and keygate entry points
            // return everything from `()` to a `Grant` or a `Rule`.
            let _ =
                env.invoke_contract::<Val>(&proposal.target, &proposal.func, proposal.args.clone());
        }
        let mut done = proposal.clone();
        done.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &done);

        // Executed proposals stay readable by id but leave the pending set, so
        // an indexer's cursor over `live_ids` only ever holds open work.
        let mut kept = Vec::new(&env);
        let ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::LiveIds)
            .unwrap_or(Vec::new(&env));
        for candidate in ids.iter() {
            if candidate != id {
                kept.push_back(candidate);
            }
        }
        env.storage().persistent().set(&DataKey::LiveIds, &kept);

        env.events()
            .publish((symbol_short!("executed"), caller), id);
        Ok(())
    }

    /// Applies a proposal that targets this contract. Owner rotation is the
    /// only one it recognises: a self-call's arguments are decoded by hand, so
    /// a proposal cannot ask for a function the multisig has not agreed to
    /// interpret. The quorum check in `execute` is the whole authorisation — a
    /// contract cannot sign for itself, and this is where that rule stops the
    /// owner set from being rotated any other way.
    fn run_on_self(env: &Env, func: &Symbol, args: &Vec<Val>) -> Result<(), Error> {
        if *func != Symbol::new(env, "set_owners") {
            return Err(Error::UnknownSelfCall);
        }
        if args.len() != 2 {
            return Err(Error::MalformedSelfCall);
        }
        let owners: Vec<Address> = args
            .get(0)
            .ok_or(Error::MalformedSelfCall)?
            .try_into_val(env)
            .map_err(|_| Error::MalformedSelfCall)?;
        let threshold: u32 = args
            .get(1)
            .ok_or(Error::MalformedSelfCall)?
            .try_into_val(env)
            .map_err(|_| Error::MalformedSelfCall)?;
        Self::store_owners(env, &owners, threshold)
    }

    /// Applies a validated owner set. `initialize` performs the same checks
    /// before it stores, so a proposal and a fresh deployment cannot disagree
    /// about what a legal owner set is.
    fn store_owners(env: &Env, owners: &Vec<Address>, threshold: u32) -> Result<(), Error> {
        if owners.is_empty() {
            return Err(Error::EmptyOwners);
        }
        if threshold == 0 || threshold > owners.len() {
            return Err(Error::InvalidThreshold);
        }
        let mut unique = Vec::new(env);
        for owner in owners.iter() {
            if unique.contains(&owner) {
                return Err(Error::DuplicateOwner);
            }
            unique.push_back(owner);
        }
        env.storage().persistent().set(&DataKey::Owners, &unique);
        env.storage()
            .persistent()
            .set(&DataKey::Threshold, &threshold);
        env.events()
            .publish((symbol_short!("ms_owners"),), (unique, threshold));
        Ok(())
    }

    pub fn proposal(env: Env, id: u64) -> Option<Proposal> {
        env.storage().persistent().get(&DataKey::Proposal(id))
    }

    /// Open proposal ids, in submission order.
    pub fn live_ids(env: Env) -> Vec<u64> {
        let ids: Option<Vec<u64>> = env.storage().persistent().get(&DataKey::LiveIds);
        ids.unwrap_or(Vec::new(&env))
    }

    pub fn approvals(env: Env, id: u64) -> Vec<Address> {
        let proposal: Option<Proposal> = env.storage().persistent().get(&DataKey::Proposal(id));
        match proposal {
            Some(proposal) => proposal.approvals,
            None => Vec::new(&env),
        }
    }

    pub fn owners(env: Env) -> Vec<Address> {
        let owners: Option<Vec<Address>> = env.storage().persistent().get(&DataKey::Owners);
        owners.unwrap_or(Vec::new(&env))
    }

    pub fn threshold(env: Env) -> u32 {
        let value: Option<u32> = env.storage().persistent().get(&DataKey::Threshold);
        value.unwrap_or(0)
    }

    pub fn is_owner(env: Env, address: Address) -> bool {
        Self::owners(env.clone()).contains(&address)
    }

    fn load(env: &Env, id: u64) -> Result<Proposal, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(id))
            .ok_or(Error::ProposalNotFound)
    }

    /// Owner-set membership is checked here; the signature itself is enforced
    /// by the host when `caller.require_auth()` runs.
    fn require_owner(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        if !Self::owners(env.clone()).contains(caller) {
            return Err(Error::NotAnOwner);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
