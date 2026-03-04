/// EIP-1559 baseFee update rule (London).
///
/// target_gas = gas_limit / 2
/// delta = baseFee * (gas_used - target_gas) / target_gas / 8
///
/// This is the canonical formula. We keep it integer.
pub fn next_base_fee(base_fee: u64, gas_used: u64, gas_limit: u64) -> u64 {
    if gas_limit == 0 { return base_fee; }
    let target = gas_limit / 2;
    if target == 0 { return base_fee; }

    if gas_used == target {
        return base_fee;
    }

    // base_fee_change = max(1, base_fee * abs(gas_used-target) / target / 8) for increases
    // for decreases: base_fee - base_fee * (target-gas_used) / target / 8
    if gas_used > target {
        let gas_delta = gas_used - target;
        let mut change = (base_fee as u128) * (gas_delta as u128);
        change /= target as u128;
        change /= 8u128;
        let change_u = change as u64;
        base_fee.saturating_add(std::cmp::max(1, change_u))
    } else {
        let gas_delta = target - gas_used;
        let mut change = (base_fee as u128) * (gas_delta as u128);
        change /= target as u128;
        change /= 8u128;
        let change_u = change as u64;
        base_fee.saturating_sub(change_u)
    }
}
