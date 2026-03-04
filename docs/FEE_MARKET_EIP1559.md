# Fee market (EIP-1559) notes (MEGA v7)

To be Ethereum-tool compatible:
- Basefee updates per block based on gas used vs target
- Effective gas price = min(maxFeePerGas, basefee + maxPriorityFeePerGas)

This package doesn't fully wire basefee into consensus yet; it's the next integration step.
