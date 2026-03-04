# VM Overview (MEGA v4)

This package adds a **minimal EVM-like VM scaffold** intended for iteration.

## Goals
- Deterministic execution
- Gas metering
- Contract deploy + call
- State interface abstraction (KV + account model optional)

## Non-goals (for this scaffold)
- Full EVM compatibility
- Precompiles, EC crypto
- Advanced JIT
- Formal verification

## Components
- `src/vm/`: bytecode, interpreter, gas, errors
- `src/types/tx_vm.rs`: VM transaction types (deploy/call)
- `src/execution/vm_executor.rs`: wiring point to execute a VM tx against state

## Next steps
- Decide compatibility target: full EVM, WASM (e.g., Wasmtime), Move, or custom.
- Add ABI / contract format
- Add storage trie / account model
- Add state rent / pruning
