# PoS Economics (starter spec)

This document defines a minimal but production-minded PoS model to iterate on.

## Parameters (genesis)
- `base_inflation_bps`: annual inflation basis points
- `min_stake`: minimum stake to become validator
- `slash_double_sign_bps`: slash for double-sign
- `slash_downtime_bps`: slash for excessive downtime
- `reward_split`: { validator, delegators, treasury }
- `unbonding_epochs`: how long until stake becomes withdrawable

## State
- Validators: stake, commission, status, last_seen, consensus_pubkey
- Delegations: delegator -> validator -> shares
- Treasury: collects fees and a fraction of inflation

## Transitions
- bond / delegate / undelegate / withdraw
- validator join/leave, jailing, slashing
- end-of-epoch: distribute rewards, apply inflation, update set

## Notes
This is a conservative baseline. To compete, you will need tuning, simulations,
and clear economic security assumptions.
