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

use std::process;
use serde_json::Value;

fn usage() {
    eprintln!(
        "iona-cli <command> [options]\n\nCommands:\n  status                     Show node status\n  balance <address>          Query account balance\n  nonce <address>            Query account nonce\n  kv get <key>               Query KV state entry\n  tx submit <file.json>      Submit a signed transaction JSON file\n  block get <height>         Fetch block by height\n  mempool                    Show mempool stats\n  validators                 List consensus validators and their status\n  staking info               Show staking state (validators, delegations)\n  staking delegate <val> <amt>   Show payload to delegate to validator\n  staking undelegate <val> <amt> Show payload to undelegate from validator\n  staking withdraw <val>     Show payload to withdraw unbonded stake\n  staking register <bps>     Show payload to register as validator\n  staking deregister         Show payload to deregister as validator\n  gov propose <action>...    Submit governance proposal\n                               add_validator <pk_hex> <stake>\n                               remove_validator <pk_hex>\n                               set_param <key> <value>\n  gov vote <id> yes|no       Vote on proposal id\n  gov list                   List pending proposals\n  vm state                   List all deployed contracts\n  vm deploy <init_code_hex>  Show tx template to deploy a contract\n  vm call <contract> [data]  Execute a read-only call against a contract\n  faucet <address> <amount>  Request faucet tokens (devnet only)\n\nOptions:\n  --rpc <url>   RPC endpoint (default: http://127.0.0.1:8080)\n\nExamples:\n  iona-cli status\n  iona-cli balance deadbeefcafe0000000000000000000000000000\n  iona-cli tx submit my_tx.json\n  iona-cli staking info\n  iona-cli staking delegate alice 100000\n  iona-cli gov propose add_validator abc123 1000\n  iona-cli gov vote 0 yes\n  iona-cli vm state\n  iona-cli vm deploy 600160005500\n  iona-cli vm call abcdef1234...32bytes 00000001\n  iona-cli faucet deadbeef 1000\n"
    );
}

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
    "http://127.0.0.1:8080".to_string()
}

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

fn http_get(url: &str) -> Result<Value, String> {
    let response = ureq::get(url)
        .call()
        .map_err(|e| format!("HTTP GET {url}: {e}"))?;
    response.into_json::<Value>().map_err(|e| format!("JSON parse: {e}"))
}

fn http_post(url: &str, body: Value) -> Result<Value, String> {
    let response = ureq::post(url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| format!("HTTP POST {url}: {e}"))?;
    response.into_json::<Value>().map_err(|e| format!("JSON parse: {e}"))
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()));
}

fn die(msg: &str) -> ! {
    eprintln!("Error: {msg}");
    process::exit(1);
}

fn require(args: &[String], idx: usize, usage_hint: &str) -> String {
    args.get(idx).cloned().unwrap_or_else(|| {
        eprintln!("Usage: {usage_hint}");
        process::exit(1)
    })
}

fn cmd_status(rpc: &str) {
    match http_get(&format!("{rpc}/health")) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn cmd_balance(rpc: &str, address: &str) {
    match http_get(&format!("{rpc}/state")) {
        Ok(v) => {
            let norm = address.to_lowercase().trim_start_matches("0x").to_string();
            let bal = v["balances"][&norm]
                .as_u64()
                .or_else(|| v["balances"][address].as_u64())
                .unwrap_or(0);
            println!("Balance of {address}: {bal}");
        }
        Err(e) => die(&e),
    }
}

fn cmd_nonce(rpc: &str, address: &str) {
    match http_get(&format!("{rpc}/state")) {
        Ok(v) => {
            let norm = address.to_lowercase().trim_start_matches("0x").to_string();
            let nonce = v["nonces"][&norm]
                .as_u64()
                .or_else(|| v["nonces"][address].as_u64())
                .unwrap_or(0);
            println!("Nonce of {address}: {nonce}");
        }
        Err(e) => die(&e),
    }
}

fn cmd_kv_get(rpc: &str, key: &str) {
    match http_get(&format!("{rpc}/state")) {
        Ok(v) => {
            match v["kv"].get(key) {
                Some(val) if !val.is_null() => println!("{key} = {val}"),
                _ => println!("Key '{key}' not found"),
            }
        }
        Err(e) => die(&e),
    }
}

fn cmd_tx_submit(rpc: &str, file: &str) {
    let data = std::fs::read_to_string(file)
        .unwrap_or_else(|e| die(&format!("Cannot read '{file}': {e}")));
    let tx: Value = serde_json::from_str(&data)
        .unwrap_or_else(|e| die(&format!("Invalid JSON in '{file}': {e}")));
    match http_post(&format!("{rpc}/tx"), tx) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn cmd_block_get(rpc: &str, height: &str) {
    let h: u64 = height.parse().unwrap_or_else(|_| die(&format!("Invalid height: {height}")));
    match http_get(&format!("{rpc}/block/{h}")) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn cmd_mempool(rpc: &str) {
    match http_get(&format!("{rpc}/mempool")) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn cmd_validators(rpc: &str) {
    match http_get(&format!("{rpc}/validators")) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn cmd_gov_list(rpc: &str) {
    match http_get(&format!("{rpc}/governance")) {
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
    let payload = format!("gov {}", args.join(" "));
    println!("Governance payload to include in tx: {payload}");
    println!();
    println!("Build and sign a Tx with this payload, then submit with: iona-cli tx submit <file>");
    println!("Example tx JSON:");
    let example = serde_json::json!({
        "from": "<your_address>",
        "nonce": 0,
        "gas_limit": 21000,
        "max_fee_per_gas": 1,
        "max_priority_fee_per_gas": 1,
        "payload": payload,
        "chain_id": 6126151,
        "pubkey": "<your_pubkey_hex>",
        "signature": "<your_signature_hex>"
    });
    println!("{}", serde_json::to_string_pretty(&example).unwrap());
}

fn cmd_gov_vote(id_str: &str, vote_str: &str) {
    let id: u64 = id_str.parse().unwrap_or_else(|_| die(&format!("Invalid proposal id: {id_str}")));
    let yes = match vote_str.to_lowercase().as_str() {
        "yes" | "true" | "1" => true,
        "no" | "false" | "0" => false,
        _ => die("Vote must be 'yes' or 'no'"),
    };
    let payload = format!("gov vote {} {}", id, if yes { "yes" } else { "no" });
    println!("Governance vote payload to include in tx: {payload}");
    println!();
    println!("Build and sign a Tx with this payload, then submit with: iona-cli tx submit <file>");
}

fn cmd_faucet(rpc: &str, address: &str, amount: &str) {
    let amt: u64 = amount.parse().unwrap_or_else(|_| die(&format!("Invalid amount: {amount}")));
    match http_get(&format!("{rpc}/faucet/{address}/{amt}")) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

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
                    print_staking_tx_help("delegate", &format!("{val} {amt}"),
                        &format!("stake delegate {val} {amt}"));
                }
                Some("undelegate") => {
                    let val = require(&pos, 2, "staking undelegate <validator> <amount>");
                    let amt = require(&pos, 3, "staking undelegate <validator> <amount>");
                    print_staking_tx_help("undelegate", &format!("{val} {amt}"),
                        &format!("stake undelegate {val} {amt}"));
                }
                Some("withdraw") => {
                    let val = require(&pos, 2, "staking withdraw <validator>");
                    print_staking_tx_help("withdraw", &val,
                        &format!("stake withdraw {val}"));
                }
                Some("register") => {
                    let commission = require(&pos, 2, "staking register <commission_bps>");
                    print_staking_tx_help("register", &commission,
                        &format!("stake register {commission}"));
                }
                Some("deregister") => {
                    print_staking_tx_help("deregister", "", "stake deregister");
                }
                Some(sub) => {
                    eprintln!("Unknown staking subcommand: {sub}");
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

        Some("faucet") => {
            let addr = require(&pos, 1, "faucet <address> <amount>");
            let amount = require(&pos, 2, "faucet <address> <amount>");
            cmd_faucet(&rpc, &addr, &amount);
        }

        Some("vm") => {
            match pos.get(1).map(String::as_str) {
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
                    eprintln!("Unknown vm subcommand: {sub}");
                    eprintln!("Usage: vm <state|call|deploy>");
                    process::exit(1);
                }
            }
        }

        Some(cmd) => {
            eprintln!("Unknown command: {cmd}");
            usage();
            process::exit(1);
        }

        None => {
            usage();
        }
    }
}

// ── Staking commands added in PoS release ────────────────────────────────

fn cmd_staking_info(rpc: &str) {
    match http_get(&format!("{rpc}/staking")) {
        Ok(v) => print_json(&v),
        Err(e) => die(&e),
    }
}

fn print_staking_tx_help(action: &str, args_desc: &str, payload_template: &str) {
    println!("Staking payload for '{action} {args_desc}':");
    println!("  {payload_template}");
    println!();
    println!("Build and sign a Tx with this payload, then submit with: iona-cli tx submit <file>");
    let example = serde_json::json!({
        "from": "<your_address>",
        "nonce": 0,
        "gas_limit": 30000,
        "max_fee_per_gas": 1,
        "max_priority_fee_per_gas": 1,
        "payload": payload_template,
        "chain_id": 6126151,
        "pubkey": "<your_pubkey_hex>",
        "signature": "<your_signature_hex>"
    });
    println!("{}", serde_json::to_string_pretty(&example).unwrap());
}

// ── VM commands (v26.0.0) ─────────────────────────────────────────────────

/// GET /vm/state — list all deployed contracts.
fn cmd_vm_state(rpc: &str) {
    match http_get(&format!("{rpc}/vm/state")) {
        Ok(v)  => print_json(&v),
        Err(e) => die(&e),
    }
}

/// POST /vm/call — read-only (view) call against a deployed contract.
fn cmd_vm_call(rpc: &str, contract: &str, calldata: &str) {
    let body = serde_json::json!({
        "contract":  contract,
        "calldata":  calldata,
        "gas_limit": 500_000u64,
    });
    let url = format!("{rpc}/vm/call");
    let resp = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(&body);
    match resp {
        Ok(r) => {
            match r.into_json::<serde_json::Value>() {
                Ok(v)  => print_json(&v),
                Err(e) => die(&format!("JSON decode error: {e}")),
            }
        }
        Err(e) => die(&format!("HTTP error: {e}")),
    }
}

/// Print instructions for deploying a contract.
fn print_vm_deploy_help(init_code_hex: &str) {
    println!("VM deploy payload for init_code: {init_code_hex}");
    println!();
    println!("Build and sign a Tx with this payload, then submit with: iona-cli tx submit <file>");
    println!();
    println!("Payload format:  vm deploy <init_code_hex>");
    println!("After execution, the contract address is returned in the receipt 'data' field.");
    println!();
    let example = serde_json::json!({
        "from": "<your_address>",
        "nonce": 0,
        "gas_limit": 1_000_000,
        "max_fee_per_gas": 1,
        "max_priority_fee_per_gas": 1,
        "payload": format!("vm deploy {init_code_hex}"),
        "chain_id": 6126151,
        "pubkey": "<your_pubkey_hex>",
        "signature": "<your_signature_hex>"
    });
    println!("{}", serde_json::to_string_pretty(&example).unwrap());
    println!();
    println!("After deploy, call the contract with:");
    println!("  iona-cli vm call <contract_address_from_receipt> <calldata_hex>");
}
