use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalKind {
    ParamChange { key: String, value: String },
    Upgrade { target_version: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub kind: ProposalKind,
    pub deposit: u128,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub executed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GovernanceState {
    pub next_id: u64,
    pub proposals: BTreeMap<u64, Proposal>,
    pub votes: BTreeMap<(u64, String), bool>, // (proposal_id, voter) -> yes/no
}

impl GovernanceState {
    pub fn submit(&mut self, kind: ProposalKind, deposit: u128, start_epoch: u64, voting_epochs: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let p = Proposal {
            id,
            kind,
            deposit,
            start_epoch,
            end_epoch: start_epoch.saturating_add(voting_epochs),
            executed: false,
        };
        self.proposals.insert(id, p);
        id
    }

    pub fn vote(&mut self, proposal_id: u64, voter: String, yes: bool) {
        self.votes.insert((proposal_id, voter), yes);
    }

    pub fn tally(&self, proposal_id: u64) -> (u64, u64) {
        let mut yes = 0;
        let mut no = 0;
        for ((pid, _), v) in self.votes.iter() {
            if *pid != proposal_id { continue; }
            if *v { yes += 1 } else { no += 1 }
        }
        (yes, no)
    }
}
