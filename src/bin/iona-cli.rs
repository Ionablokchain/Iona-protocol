//! iona-cli — Command-line interface for IONA node
//!
//! Commands:
//!   status          Show node health and best height
//!   tx submit       Submit a signed transaction JSON
//!   balance         Query account balance
//!   nonce           Query account nonce
//!   kv get          Query KV state entry
//!   gov propose     Submit a governance proposal  
//!   gov vote        Vote on a governance proposal
//!   gov list        List pending proposals
//!   validators      Show validators list
//!   block get       Fetch block by height
//!   mempool         Show mempool stats
//!   faucet          Request test tokens (if enabled)
//!   staking info    Show staking state
//!   staking delegate ...  Generate delegate tx payload
//!   staking undelegate ... Generate undelegate tx payload
//!   staking withdraw ...   Generate withdraw tx payload
//!   staking register ...   Generate register validator tx payload
//!   staking deregister     Generate deregister validator tx payload
//!   vm state        List deployed contracts
//!   vm call         Read‑only call to a contract
//!   vm deploy       Generate deploy contract tx payload

use std::process;
use serde_json::Value;

// Default RPC endpoint
const DEFAULT_RPC: &str = "http://127.0.0.1:8080";
// Default chain ID (should match node configuration)
const DEFAULT_CHAIN_ID: u64 = 6126151;
// Default gas limits for different operations
const GAS_LIMIT_TX: u64 = 21_000;
const GAS_LIMIT_STAKING: u64 = 30_000;
const GAS_LIMIT_VM_DEPLOY: u64 = 1_000_000;
const GAS_LIMIT_VM_CALL: u64 = 500_000;

fn usage() {
    eprintln!(
        "iona-cli <command> [options] [args...]

Commands:
  status                     Show node status
  balance <address>          Query account balance
  nonce <address>            Query account nonce
  kv get <key>               Query KV state entry
  tx submit <file.json>      Submit a signed transaction JSON file
  block get <height>         Fetch block by height
  mempool                    Show mempool stats
  validators                 List consensus validators and their status
  staking info               Show staking state (validators, delegations)
  staking delegate <val> <amt>   Show payload to delegate to validator
  staking undelegate <val> <amt> Show payload to undelegate from validator
  staking withdraw <val>     Show payload to withdraw unbonded stake
  staking register <bps>     Show payload to register as validator
  staking deregister         Show payload to deregister as validator
  gov propose <action>...    Submit governance proposal
                               add_validator <pk_hex> <stake>
                               remove_validator <pk_hex>
                               set_param <key> <value>
  gov vote <id> yes|no       Vote on proposal id
  gov list                   List pending proposals
  vm state                   List all deployed contracts
  vm deploy <init_code_hex>  Show tx template to deploy a contract
  vm call <contract> [data]  Execute a read‑only call against a contract
  faucet <address> <amount>  Request faucet tokens (devnet only)

Options:
  --rpc <url>   RPC endpoint (default: http://127.0.0.1:8080)

Examples:
  iona-cli status
  iona-cli balance deadbeefcafe0000000000000000000000000000
  iona-cli tx submit my_tx.json
  iona-cli staking info
  iona-cli staking delegate alice 100000
  iona-cli gov propose add_validator abc123 1000
  iona-cli gov vote 0 yes
  iona-cli vm state
  iona-cli vm deploy 600160005500
  iona-cli vm call abcdef1234...32bytes 00000001
  iona-cli faucet deadbeef 1000
"
    );
}

/// Extract RPC URL from arguments (--rpc <url>)
fn rpc_url(args: &[String]) -> String {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--rpc" {
            if let Some(url) = args.get(i + 1) {
                return url.clone();
            }
        }
        i += 1;
    }
    DEFAULT_RPC.to_string()
}

/// Filter out --rpc and its value, return only positional arguments
fn filter_positional(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--rpc" {
            i += 2;
        } else {
            out.push(args[i].clone());
            i += 1;
        }
    }
    out
}

/// Perform HTTP GET request and parse JSON
fn http_get(url: &str) -> Result<Value, String> {
    let response = ureq::get(url)
        .call()
        .map_err(|e| format!("HTTP GET {}: {}", url, e))?;
    response.into_json::<Value>()
        .map_err(|e| format!("JSON parse error: {}", e))
}

/// Perform HTTP POST request with JSON body and parse response
fn http_post(url: &str, body: Value) -> Result<Value, String> {
    let response = ureq::post(url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| format!("HTTP POST {}: {}", url, e))?;
    response.into_json::<Value>()
        .map_err(|e| format!("JSON parse error: {}", e))
}

/// Pretty‑print JSON value
fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()));
}

/// Exit with error message
fn die(msg: &str) -> ! {
    eprintln!("Error: {}", msg);
    process::exit(1);
}

/// Get required argument at index, or print usage and exit
fn require(args: &[String], idx: usize, usage_hint: &str) -> String {
    args.get(idx).cloned().unwrap_or_else(|| {
        eprintln!("Usage: {}", usage_hint);
        process::exit(1)
    })
}

/// Parse a u64 amount from string, with error handling
fn parse_amount(s: &str, field: &str) -> u64 {
    s.parse().unwrap_or_else(|_| die(&format!("Invalid {}: '{}'", field, s)))
}

/// Normalize address (remove 0x prefix, lowercase)
fn normalize_address(addr: &str) -> String {
    addr.trim_start_matches("0x").to_lowercase()
}

// ── Command implementations ──────────────────────────────────────────────────

fn cmd_status(rpc: &str) {
    match http_get(&format!("{}/health", rpc)) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn cmd_balance(rpc: &str, address: &str) {
    let norm = normalize_address(address);
    match http_get(&format!("{}/state", rpc)) {
        Ok(v) => {
            let bal = v["balances"][&norm].as_u64().unwrap_or(0);
            println!("Balance of {}: {}", address, bal);
        }
        Err(e) => die(&e),
    }
}

fn cmd_nonce(rpc: &str, address: &str) {
    let norm = normalize_address(address);
    match http_get(&format!("{}/state", rpc)) {
        Ok(v) => {
            let nonce = v["nonces"][&norm].as_u64().unwrap_or(0);
            println!("Nonce of {}: {}", address, nonce);
        }
        Err(e) => die(&e),
    }
}

fn cmd_kv_get(rpc: &str, key: &str) {
    match http_get(&format!("{}/state", rpc)) {
        Ok(v) => {
            match v["kv"].get(key) {
                Some(val) if !val.is_null() => println!("{} = {}", key, val),
                _ => println!("Key '{}' not found", key),
            }
        }
        Err(e) => die(&e),
    }
}

fn cmd_tx_submit(rpc: &str, file: &str) {
    let data = std::fs::read_to_string(file)
        .unwrap_or_else(|e| die(&format!("Cannot read '{}': {}", file, e)));
    let tx: Value = serde_json::from_str(&data)
        .unwrap_or_else(|e| die(&format!("Invalid JSON in '{}': {}", file, e)));

    match http_post(&format!("{}/tx", rpc), tx) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn cmd_block_get(rpc: &str, height: &str) {
    let h = parse_amount(height, "height");
    match http_get(&format!("{}/block/{}", rpc, h)) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn cmd_mempool(rpc: &str) {
    match http_get(&format!("{}/mempool", rpc)) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn cmd_validators(rpc: &str) {
    match http_get(&format!("{}/validators", rpc)) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn cmd_staking_info(rpc: &str) {
    match http_get(&format!("{}/staking", rpc)) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

/// Generate a generic payload for staking actions and print help
fn print_staking_payload(action: &str, args: &str, usage_hint: &str) {
    let payload = format!("stake {} {}", action, args).trim().to_string();
    println!("Staking payload: {}", payload);
    println!();
    println!("Build and sign a Tx with this payload, then submit with: iona-cli tx submit <file>");
    println!();
    let example = serde_json::json!({
        "from": "<your_address>",
        "nonce": 0,
        "gas_limit": GAS_LIMIT_STAKING,
        "max_fee_per_gas": 1,
        "max_priority_fee_per_gas": 1,
        "payload": payload,
        "chain_id": DEFAULT_CHAIN_ID,
        "pubkey": "<your_pubkey_hex>",
        "signature": "<your_signature_hex>"
    });
    println!("Example JSON:");
    println!("{}", serde_json::to_string_pretty(&example).unwrap());
}

fn cmd_gov_list(rpc: &str) {
    match http_get(&format!("{}/governance", rpc)) {
        Ok(v) => print_json(&v),
        Err(_) => {
            eprintln!("Governance endpoint not available on this node.");
            eprintln!("Governance actions are submitted as signed transactions with 'gov' payload prefix.");
        }
    }
}

fn cmd_gov_propose(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: gov propose <action> [args...]");
        eprintln!("  add_validator <pk_hex> <stake>");
        eprintln!("  remove_validator <pk_hex>");
        eprintln!("  set_param <key> <value>");
        process::exit(1);
    }

    let action = &args[0];
    let payload = match action.as_str() {
        "add_validator" => {
            if args.len() < 3 {
                die("add_validator requires <pk_hex> <stake>");
            }
            let pk = &args[1];
            let stake = parse_amount(&args[2], "stake");
            format!("gov add_validator {} {}", pk, stake)
        }
        "remove_validator" => {
            if args.len() < 2 {
                die("remove_validator requires <pk_hex>");
            }
            let pk = &args[1];
            format!("gov remove_validator {}", pk)
        }
        "set_param" => {
            if args.len() < 3 {
                die("set_param requires <key> <value>");
            }
            let key = &args[1];
            let value = &args[2];
            format!("gov set_param {} {}", key, value)
        }
        _ => die(&format!("Unknown governance action: {}", action)),
    };

    println!("Governance payload to include in tx: {}", payload);
    println!();
    println!("Build and sign a Tx with this payload, then submit with: iona-cli tx submit <file>");
    println!();
    let example = serde_json::json!({
        "from": "<your_address>",
        "nonce": 0,
        "gas_limit": GAS_LIMIT_TX,
        "max_fee_per_gas": 1,
        "max_priority_fee_per_gas": 1,
        "payload": payload,
        "chain_id": DEFAULT_CHAIN_ID,
        "pubkey": "<your_pubkey_hex>",
        "signature": "<your_signature_hex>"
    });
    println!("Example JSON:");
    println!("{}", serde_json::to_string_pretty(&example).unwrap());
}

fn cmd_gov_vote(id_str: &str, vote_str: &str) {
    let id = parse_amount(id_str, "proposal id");
    let yes = match vote_str.to_lowercase().as_str() {
        "yes" | "true" | "1" => true,
        "no" | "false" | "0" => false,
        _ => die("Vote must be 'yes' or 'no'"),
    };
    let payload = format!("gov vote {} {}", id, if yes { "yes" } else { "no" });
    println!("Governance vote payload: {}", payload);
    println!();
    println!("Build and sign a Tx with this payload, then submit with: iona-cli tx submit <file>");
    println!();
    let example = serde_json::json!({
        "from": "<your_address>",
        "nonce": 0,
        "gas_limit": GAS_LIMIT_TX,
        "max_fee_per_gas": 1,
        "max_priority_fee_per_gas": 1,
        "payload": payload,
        "chain_id": DEFAULT_CHAIN_ID,
        "pubkey": "<your_pubkey_hex>",
        "signature": "<your_signature_hex>"
    });
    println!("Example JSON:");
    println!("{}", serde_json::to_string_pretty(&example).unwrap());
}

fn cmd_faucet(rpc: &str, address: &str, amount: &str) {
    let amt = parse_amount(amount, "amount");
    let norm_addr = normalize_address(address);
    match http_get(&format!("{}/faucet/{}/{}", rpc, norm_addr, amt)) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn cmd_vm_state(rpc: &str) {
    match http_get(&format!("{}/vm/state", rpc)) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn cmd_vm_call(rpc: &str, contract: &str, calldata: &str) {
    let body = serde_json::json!({
        "contract": contract,
        "calldata": calldata,
        "gas_limit": GAS_LIMIT_VM_CALL,
    });
    match http_post(&format!("{}/vm/call", rpc), body) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn print_vm_deploy_help(init_code_hex: &str) {
    let payload = format!("vm deploy {}", init_code_hex);
    println!("VM deploy payload: {}", payload);
    println!();
    println!("After execution, the contract address is returned in the receipt 'data' field.");
    println!();
    println!("Build and sign a Tx with this payload, then submit with: iona-cli tx submit <file>");
    println!();
    let example = serde_json::json!({
        "from": "<your_address>",
        "nonce": 0,
        "gas_limit": GAS_LIMIT_VM_DEPLOY,
        "max_fee_per_gas": 1,
        "max_priority_fee_per_gas": 1,
        "payload": payload,
        "chain_id": DEFAULT_CHAIN_ID,
        "pubkey": "<your_pubkey_hex>",
        "signature": "<your_signature_hex>"
    });
    println!("Example JSON:");
    println!("{}", serde_json::to_string_pretty(&example).unwrap());
    println!();
    println!("After deploy, call the contract with:");
    println!("  iona-cli vm call <contract_address_from_receipt> <calldata_hex>");
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();

    if raw.is_empty() || raw[0] == "--help" || raw[0] == "-h" || raw[0] == "help" {
        usage();
        return;
    }

    let rpc = rpc_url(&raw);
    let pos = filter_positional(&raw);

    match pos.get(0).map(|s| s.as_str()) {
        Some("status") => cmd_status(&rpc),

        Some("balance") => {
            let addr = require(&pos, 1, "balance <address>");
            cmd_balance(&rpc, &addr);
        }

        Some("nonce") => {
            let addr = require(&pos, 1, "nonce <address>");
            cmd_nonce(&rpc, &addr);
        }

        Some("kv") => {
            if pos.get(1).map(|s| s.as_str()) == Some("get") {
                let key = require(&pos, 2, "kv get <key>");
                cmd_kv_get(&rpc, &key);
            } else {
                die("Usage: kv get <key>");
            }
        }

        Some("tx") => {
            if pos.get(1).map(|s| s.as_str()) == Some("submit") {
                let file = require(&pos, 2, "tx submit <file.json>");
                cmd_tx_submit(&rpc, &file);
            } else {
                die("Usage: tx submit <file.json>");
            }
        }

        Some("block") => {
            if pos.get(1).map(|s| s.as_str()) == Some("get") {
                let h = require(&pos, 2, "block get <height>");
                cmd_block_get(&rpc, &h);
            } else {
                die("Usage: block get <height>");
            }
        }

        Some("mempool") => cmd_mempool(&rpc),
        Some("validators") => cmd_validators(&rpc),

        Some("staking") => {
            match pos.get(1).map(|s| s.as_str()) {
                Some("info") | None => cmd_staking_info(&rpc),
                Some("delegate") => {
                    let val = require(&pos, 2, "staking delegate <validator> <amount>");
                    let amt = require(&pos, 3, "staking delegate <validator> <amount>");
                    parse_amount(&amt, "amount"); // validate
                    print_staking_payload("delegate", &format!("{} {}", val, amt), "delegate");
                }
                Some("undelegate") => {
                    let val = require(&pos, 2, "staking undelegate <validator> <amount>");
                    let amt = require(&pos, 3, "staking undelegate <validator> <amount>");
                    parse_amount(&amt, "amount");
                    print_staking_payload("undelegate", &format!("{} {}", val, amt), "undelegate");
                }
                Some("withdraw") => {
                    let val = require(&pos, 2, "staking withdraw <validator>");
                    print_staking_payload("withdraw", val, "withdraw");
                }
                Some("register") => {
                    let bps = require(&pos, 2, "staking register <commission_bps>");
                    parse_amount(&bps, "commission");
                    print_staking_payload("register", &bps, "register");
                }
                Some("deregister") => {
                    print_staking_payload("deregister", "", "deregister");
                }
                Some(sub) => {
                    eprintln!("Unknown staking subcommand: {}", sub);
                    eprintln!("Usage: staking <info|delegate|undelegate|withdraw|register|deregister>");
                    process::exit(1);
                }
            }
        }

        Some("gov") => {
            match pos.get(1).map(|s| s.as_str()) {
                Some("propose") => cmd_gov_propose(&pos[2..]),
                Some("vote") => {
                    let id = require(&pos, 2, "gov vote <id> yes|no");
                    let vote = require(&pos, 3, "gov vote <id> yes|no");
                    cmd_gov_vote(&id, &vote);
                }
                Some("list") => cmd_gov_list(&rpc),
                _ => {
                    eprintln!("Usage: gov <propose|vote|list>");
                    process::exit(1);
                }
            }
        }

        Some("vm") => {
            match pos.get(1).map(|s| s.as_str()) {
                Some("state") | None => cmd_vm_state(&rpc),
                Some("call") => {
                    let contract = require(&pos, 2, "vm call <contract_hex> [calldata_hex]");
                    let calldata = pos.get(3).cloned().unwrap_or_default();
                    cmd_vm_call(&rpc, &contract, &calldata);
                }
                Some("deploy") => {
                    let init_code = require(&pos, 2, "vm deploy <init_code_hex>");
                    print_vm_deploy_help(&init_code);
                }
                Some(sub) => {
                    eprintln!("Unknown vm subcommand: {}", sub);
                    eprintln!("Usage: vm <state|call|deploy>");
                    process::exit(1);
                }
            }
        }

        Some("faucet") => {
            let addr = require(&pos, 1, "faucet <address> <amount>");
            let amount = require(&pos, 2, "faucet <address> <amount>");
            cmd_faucet(&rpc, &addr, &amount);
        }

        Some(cmd) => {
            eprintln!("Unknown command: {}", cmd);
            usage();
            process::exit(1);
        }

        None => {
            usage();
        }
    }
}
