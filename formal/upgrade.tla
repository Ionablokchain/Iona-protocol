--------------------------- MODULE upgrade ---------------------------
\* IONA protocol upgrade safety — bounded TLA+ model with per‑validator
\* state, blocks, votes, quorums, and activation consistency.
\*
\* This model checks that a rolling protocol upgrade preserves:
\*   - Unique finality (no two correct validators finalize different blocks at same height)
\*   - Prefix safety (any two finalized blocks are on the same chain)
\*   - No equivocation (no correct validator votes twice at same height)
\*   - Quorum intersection (conflicting QCs have no common correct validator)
\*   - Activation consistency (all correct validators derive same active version from finality)
\*   - Grace window safety (no old PV blocks finalized after H + G, no new PV before H)
\*
\* Model parameters (finite domains for TLC):
\*   N, F, H, G, MaxHeight, SCHEMA_N, MaxBlocks, MaxAppHash
\*   Byzantine ⊆ Validators (|Byzantine| ≤ F)
\*
\* Note: Schema versions are included in blocks but per‑validator schema migration
\* is not modeled in this version; schema safety is left for future extensions.

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS N, F, H, G, MaxHeight, SCHEMA_N, MaxBlocks, MaxAppHash, Byzantine

ASSUME N > 0
ASSUME F >= 0
ASSUME F * 3 < N
ASSUME H > 0
ASSUME G >= 0
ASSUME MaxHeight >= H + G
ASSUME SCHEMA_N >= 1
ASSUME MaxBlocks >= MaxHeight + 1
ASSUME MaxAppHash >= 1
ASSUME Byzantine \subseteq 1..N /\ Cardinality(Byzantine) <= F

\* Validators
Validators == 1..N
Correct == Validators \ Byzantine

\* Protocol versions
PV_OLD == 1
PV_NEW == 2
PVSet == {PV_OLD, PV_NEW}

\* Schema versions (used in blocks, but per-validator schema not tracked)
SchemaSet == 1..SCHEMA_N
SCHEMA_OLD == 1
SCHEMA_NEW == SCHEMA_N

\* ---------------------------------------------------------------------------
\* Finite domains
\* ---------------------------------------------------------------------------
BlockIds == 0..MaxBlocks          \* 0 is reserved for genesis
AppHashes == 0..MaxAppHash
NULL == 0

\* ---------------------------------------------------------------------------
\* Block structure
\* ---------------------------------------------------------------------------
BlockType == [id: BlockIds, height: 0..MaxHeight, parent: BlockIds,
              pv: PVSet, schema: SchemaSet, app_hash: AppHashes,
              proposer: Validators \cup {0}]

Genesis == [
    id      |-> 0,
    height  |-> 0,
    parent  |-> NULL,
    pv      |-> PV_OLD,
    schema  |-> SCHEMA_OLD,
    app_hash|-> 0,
    proposer|-> 0
]

\* ---------------------------------------------------------------------------
\* Messages
\* ---------------------------------------------------------------------------
Vote == [voter: Validators, block_id: BlockIds, height: 1..MaxHeight]
QC == [block_id: BlockIds, height: 1..MaxHeight, signers: SUBSET Validators]

\* ---------------------------------------------------------------------------
\* Variables
\* ---------------------------------------------------------------------------
VARIABLES
    blocks,           \* set of all blocks created
    votes,            \* set of all votes cast
    qcs,              \* set of all QCs formed
    head,             \* head[v] = current head block id
    locked,           \* locked[v] = block id that v is locked on (placeholder)
    finalized_by,     \* finalized_by[v] = block id that v considers finalized
    binary_version,   \* binary_version[v] = installed binary version
    votes_cast        \* votes_cast[v][h] = block_id voted at height h (or NULL)

vars == <<blocks, votes, qcs, head, locked, finalized_by,
          binary_version, votes_cast>>

\* ---------------------------------------------------------------------------
\* Helper functions
\* ---------------------------------------------------------------------------
ExistingBlockIds == {b.id : b \in blocks}
NonGenesisBlockIds == ExistingBlockIds \ {0}
GetBlock(id) == CHOOSE b \in blocks : b.id = id

Height(b) == b.height
Parent(b) == b.parent

RECURSIVE IsAncestor(_, _)
IsAncestor(anc, desc) ==
    IF anc = desc THEN TRUE
    ELSE LET p == Parent(GetBlock(desc)) IN
         IF p = NULL THEN FALSE ELSE IsAncestor(anc, p)

\* All votes currently for a given block
VotersFor(block_id) ==
    { vote.voter : vote \in {v \in votes : v.block_id = block_id} }

\* ---------------------------------------------------------------------------
\* Global version rule (derived from finality – here simplified as height‑based)
\* In a real system, PV_at(h) would be determined by the last finalized block.
\* We keep it as a function for modeling.
\* ---------------------------------------------------------------------------
PV_at(h) == IF h < H THEN PV_OLD ELSE PV_NEW

\* Acceptability of a block version at a height (global rule)
AcceptableVersion(block_pv, h) ==
    \/ block_pv = PV_at(h)
    \/ /\ h >= H
       /\ h < H + G
       /\ block_pv = PV_OLD

\* Can validator v validate a block with given pv at height h?
\* (Depends on binary version and global acceptability)
CanValidate(v, block_pv, h) ==
    IF v \in Byzantine THEN TRUE
    ELSE
        /\ AcceptableVersion(block_pv, h)
        /\ (binary_version[v] = PV_NEW) \/ (block_pv = PV_OLD)   \* old binary cannot validate new PV blocks

\* Compatibility: can validator v apply a block (execution) given its schema?
\* In this abstract model, we do not track per‑validator schema versions,
\* so we assume all validators can apply any block. Schema safety is not
\* explicitly modeled; we only ensure that finalized blocks have acceptable
\* versions.
CompatibleSchema(v, block) == TRUE

\* ---------------------------------------------------------------------------
\* Initial state
\* ---------------------------------------------------------------------------
Init ==
    /\ blocks = {Genesis}
    /\ votes = {}
    /\ qcs = {}
    /\ head = [v \in Validators |-> 0]
    /\ locked = [v \in Validators |-> 0]
    /\ finalized_by = [v \in Validators |-> 0]
    /\ binary_version = [v \in Validators |-> IF v \in Byzantine THEN PV_NEW ELSE PV_OLD]
    /\ votes_cast = [v \in Validators |-> [h \in 1..MaxHeight |-> NULL]]

\* ---------------------------------------------------------------------------
\* Type invariants (for sanity)
\* ---------------------------------------------------------------------------
TypeOK ==
    /\ blocks \subseteq BlockType
    /\ Genesis \in blocks
    /\ votes \subseteq Vote
    /\ qcs \subseteq QC
    /\ head \in [Validators -> ExistingBlockIds]
    /\ locked \in [Validators -> ExistingBlockIds]
    /\ finalized_by \in [Validators -> ExistingBlockIds]
    /\ binary_version \in [Validators -> PVSet]
    /\ votes_cast \in [Validators -> [1..MaxHeight -> BlockIds \cup {NULL}]]
    /\ \A v \in Validators, h \in 1..MaxHeight : votes_cast[v][h] \in ExistingBlockIds \cup {NULL}

UniqueBlockIds ==
    \A b1, b2 \in blocks : b1.id = b2.id => b1 = b2

BlocksWellFormed ==
    \A b \in blocks :
        /\ b \in BlockType
        /\ b.id = 0 => b = Genesis
        /\ b.id # 0 =>
            /\ b.parent \in ExistingBlockIds
            /\ Height(GetBlock(b.parent)) + 1 = b.height

QCWellFormed ==
    \A qc \in qcs :
        /\ qc.block_id \in NonGenesisBlockIds
        /\ qc.height = Height(GetBlock(qc.block_id))
        /\ Cardinality(qc.signers) * 3 > N * 2
        /\ qc.signers \subseteq VotersFor(qc.block_id)   \* signers must be among voters for that block

\* ---------------------------------------------------------------------------
\* Actions
\* ---------------------------------------------------------------------------

\* Upgrade binary (rolling upgrade)
Upgrade(v) ==
    /\ v \in Correct
    /\ binary_version[v] = PV_OLD
    /\ binary_version' = [binary_version EXCEPT ![v] = PV_NEW]
    /\ UNCHANGED <<blocks, votes, qcs, head, locked, finalized_by, votes_cast>>

\* Propose a new block.
Propose(v, parent_id, pv, schema, app_hash) ==
    /\ v \in Validators
    /\ v \notin Byzantine               \* we don't model byzantine proposals here
    /\ parent_id \in ExistingBlockIds
    LET parent == GetBlock(parent_id) IN
    /\ parent.height < MaxHeight
    /\ CanValidate(v, pv, parent.height + 1)
    /\ AcceptableVersion(pv, parent.height + 1)
    \* Compute next block id
    LET maxId == Max({b.id : b \in blocks})
        new_id == maxId + 1
    IN
    /\ new_id <= MaxBlocks
    /\ blocks' = blocks \cup {[
        id      |-> new_id,
        height  |-> parent.height + 1,
        parent  |-> parent_id,
        pv      |-> pv,
        schema  |-> schema,
        app_hash|-> app_hash,
        proposer|-> v
    ]}
    /\ UNCHANGED <<votes, qcs, head, locked, finalized_by, binary_version, votes_cast>>

\* A validator votes for a block.
VoteForBlock(v, block_id) ==
    /\ v \in Validators
    /\ block_id \in NonGenesisBlockIds   \* cannot vote on genesis
    LET block == GetBlock(block_id) IN
    /\ v \notin Byzantine => CanValidate(v, block.pv, block.height)
    \* No vote at this height yet (prevents equivocation)
    /\ votes_cast[v][block.height] = NULL
    \* Update votes_cast
    /\ votes_cast' = [votes_cast EXCEPT ![v][block.height] = block_id]
    \* Add vote to votes set
    /\ votes' = votes \cup {[voter |-> v, block_id |-> block_id, height |-> block.height]}
    /\ UNCHANGED <<blocks, qcs, head, locked, finalized_by, binary_version>>

\* Form a QC if enough votes for a block.
FormQC(block_id) ==
    /\ block_id \in NonGenesisBlockIds   \* cannot form QC for genesis
    LET block == GetBlock(block_id) IN
    LET votes_for_block == {vote \in votes : vote.block_id = block_id} IN
    LET supporters == {vote.voter : vote \in votes_for_block} IN
    /\ Cardinality(supporters) * 3 > N * 2   \* 2/3+ quorum
    /\ qcs' = qcs \cup {[block_id |-> block_id, height |-> block.height, signers |-> supporters]}
    /\ UNCHANGED <<blocks, votes, head, locked, finalized_by, binary_version, votes_cast>>

\* A correct validator finalizes a block.
Finalize(v, block_id) ==
    /\ v \in Correct
    /\ block_id \in NonGenesisBlockIds   \* cannot finalize genesis
    LET block == GetBlock(block_id) IN
    \* Must have a QC for this block
    /\ \E qc \in qcs : qc.block_id = block_id
    \* Validator must be able to validate the block (binary compatibility)
    /\ CanValidate(v, block.pv, block.height)
    \* Finality must be monotonic in height
    /\ finalized_by[v] = 0 \/ Height(block) >= Height(GetBlock(finalized_by[v]))
    \* The block must be on the same chain as previous finalized (ancestor)
    /\ finalized_by[v] = 0 \/ IsAncestor(finalized_by[v], block_id)
    \* Update finalized_by
    /\ finalized_by' = [finalized_by EXCEPT ![v] = block_id]
    \* Also update head and locked (simplified)
    /\ head' = [head EXCEPT ![v] = block_id]
    /\ locked' = [locked EXCEPT ![v] = block_id]
    /\ UNCHANGED <<blocks, votes, qcs, binary_version, votes_cast>>

\* ---------------------------------------------------------------------------
\* Next state
\* ---------------------------------------------------------------------------
Next ==
    \/ \E v \in Validators: Upgrade(v)
    \/ \E v \in Validators, p \in BlockIds, pv \in PVSet, sc \in SchemaSet, ah \in AppHashes:
         Propose(v, p, pv, sc, ah)
    \/ \E v \in Validators, b \in NonGenesisBlockIds: VoteForBlock(v, b)
    \/ \E b \in NonGenesisBlockIds: FormQC(b)
    \/ \E v \in Validators, b \in NonGenesisBlockIds: Finalize(v, b)

\* ---------------------------------------------------------------------------
\* Derived values and consistency invariants
\* ---------------------------------------------------------------------------

DerivedActivePV(v) ==
    IF finalized_by[v] = 0
    THEN PV_OLD
    ELSE PV_at(Height(GetBlock(finalized_by[v])))

\* Whether a block is on the finalized chain of validator v
OnFinalizedChain(v, b) ==
    /\ finalized_by[v] # 0
    /\ b \in ExistingBlockIds
    /\ IsAncestor(b, finalized_by[v])

HeadConsistent ==
    \A v \in Correct :
        /\ finalized_by[v] # 0
        /\ head[v] # 0
        => IsAncestor(finalized_by[v], head[v])

\* Locked is a placeholder; we don't enforce strong invariants yet.
LockedConsistent ==
    \A v \in Correct :
        /\ locked[v] # 0
        /\ head[v] # 0
        => IsAncestor(locked[v], head[v]) \/ IsAncestor(head[v], locked[v])

\* ---------------------------------------------------------------------------
\* Safety invariants
\* ---------------------------------------------------------------------------

\* Helper: correct validators' finalized blocks are always existing and have QC
FinalizedValid ==
    \A v \in Correct :
        finalized_by[v] # 0 =>
            /\ finalized_by[v] \in ExistingBlockIds
            /\ \E qc \in qcs : qc.block_id = finalized_by[v]

\* S1: Unique finality – no two correct validators finalize different blocks at the same height.
UniqueFinality ==
    \A v1, v2 \in Correct, b1, b2 \in BlockIds :
        /\ finalized_by[v1] = b1 /\ b1 # 0
        /\ finalized_by[v2] = b2 /\ b2 # 0
        /\ Height(GetBlock(b1)) = Height(GetBlock(b2))
        => b1 = b2

\* S2: Prefix safety – any two finalized blocks are on the same chain (ancestor relationship).
PrefixSafety ==
    \A v1, v2 \in Correct :
        LET b1 == finalized_by[v1]
            b2 == finalized_by[v2]
        IN
        /\ b1 # 0 /\ b2 # 0
        => IsAncestor(b1, b2) \/ IsAncestor(b2, b1)

\* S3: No correct validator votes twice at the same height.
NoEquivocation ==
    \A v \in Correct, h \in 1..MaxHeight :
        Cardinality({vote \in votes : vote.voter = v /\ vote.height = h}) <= 1

\* S4: Quorum intersection – conflicting QCs (different block at same height) have no common correct validator.
QuorumIntersection ==
    \A qc1, qc2 \in qcs :
        /\ qc1.block_id # qc2.block_id
        /\ qc1.height = qc2.height
        => (qc1.signers \cap qc2.signers) \subseteq Byzantine

\* S5: Before activation, no block on any correct validator's finalized chain has PV_NEW.
BeforeActivationOnlyOld ==
    \A v \in Correct, b \in ExistingBlockIds :
        /\ OnFinalizedChain(v, b)
        /\ Height(GetBlock(b)) < H
        => GetBlock(b).pv = PV_OLD

\* S6: After activation + grace, no block on any correct validator's finalized chain has PV_OLD.
AfterGraceOnlyNew ==
    \A v \in Correct, b \in ExistingBlockIds :
        /\ OnFinalizedChain(v, b)
        /\ Height(GetBlock(b)) >= H + G
        => GetBlock(b).pv = PV_NEW

\* S7: Every block on any correct validator's finalized chain is acceptable according to global rule.
FinalizedAcceptable ==
    \A v \in Correct, b \in ExistingBlockIds :
        /\ OnFinalizedChain(v, b)
        => AcceptableVersion(GetBlock(b).pv, Height(GetBlock(b)))

\* S8: Activation consistency – all correct validators that have finalized the same height
\*     derive the same active PV (this is a derived consistency check).
ActivationConsistency ==
    \A v1, v2 \in Correct :
        /\ finalized_by[v1] # 0
        /\ finalized_by[v2] # 0
        /\ Height(GetBlock(finalized_by[v1])) = Height(GetBlock(finalized_by[v2]))
        => DerivedActivePV(v1) = DerivedActivePV(v2)

\* Combined safety invariant (including type checks and well‑formedness)
Safety ==
    /\ TypeOK
    /\ UniqueBlockIds
    /\ BlocksWellFormed
    /\ QCWellFormed
    /\ FinalizedValid
    /\ UniqueFinality
    /\ PrefixSafety
    /\ NoEquivocation
    /\ QuorumIntersection
    /\ BeforeActivationOnlyOld
    /\ AfterGraceOnlyNew
    /\ FinalizedAcceptable
    /\ ActivationConsistency
    /\ HeadConsistent
    \* /\ LockedConsistent   \* optional, not fully enforced yet

\* ---------------------------------------------------------------------------
\* Liveness (sketched, not model‑checked)
\* ---------------------------------------------------------------------------
\* (Placeholder – not part of safety checking)

\* ---------------------------------------------------------------------------
\* Spec
\* ---------------------------------------------------------------------------
Spec == Init /\ [][Next]_vars

THEOREM Spec => []Safety

\* ---------------------------------------------------------------------------
\* TLC configuration suggestions
\* ---------------------------------------------------------------------------
\* CONSTANTS
\*   N = 4
\*   F = 1
\*   H = 5
\*   G = 2
\*   MaxHeight = 8
\*   SCHEMA_N = 2
\*   MaxBlocks = 10
\*   MaxAppHash = 5
\*   Byzantine = {4}
\*
\* INVARIANT Safety
\*
\* Run with:
\*   TLC upgrade.tla -config upgrade.cfg -depth 30 -workers auto

=============================================================================
