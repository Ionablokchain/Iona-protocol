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
//!   audit verify    Verify the tamper-evident hashchain audit log
//!
//! Ops commands (v28.3):
//!   doctor          Run node diagnostics (ports, permissions, disk, peers, time drift)
//!   upgrade         Guided safe upgrade with rollback guidance
//!   backup          Create a snapshot backup of node data
//!   restore         Restore node data from a snapshot backup
//!   keys check      Validate key files (permissions, format, cert expiry)
//!
//! Security commands (v28.4):
//!   cert rotate     Generate and hot-reload a new mTLS admin certificate
//!   cert status     Show current cert subject and expiry
//!   support-bundle  Collect a diagnostic archive for support / incident review
//!   rbac check      Test whether an identity is allowed on an endpoint
//!   rbac export     Print the current RBAC policy TOML
//!   audit export    Export last N audit log entries to stdout
//!   audit tail      Stream the audit log in real-time (--follow)

use serde_json::Value;
use std::process;

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
    response
        .into_json::<Value>()
        .map_err(|e| format!("JSON parse: {e}"))
}

fn http_post(url: &str, body: Value) -> Result<Value, String> {
    let response = ureq::post(url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| format!("HTTP POST {url}: {e}"))?;
    response
        .into_json::<Value>()
        .map_err(|e| format!("JSON parse: {e}"))
}

fn print_json(v: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
    );
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
        Ok(v) => match v["kv"].get(key) {
            Some(val) if !val.is_null() => println!("{key} = {val}"),
            _ => println!("Key '{key}' not found"),
        },
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
    let h: u64 = height
        .parse()
        .unwrap_or_else(|_| die(&format!("Invalid height: {height}")));
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
    let id: u64 = id_str
        .parse()
        .unwrap_or_else(|_| die(&format!("Invalid proposal id: {id_str}")));
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
    let amt: u64 = amount
        .parse()
        .unwrap_or_else(|_| die(&format!("Invalid amount: {amount}")));
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

        Some("staking") => match pos.get(1).map(|s| s.as_str()) {
            Some("info") | None => cmd_staking_info(&rpc),
            Some("delegate") => {
                let val = require(&pos, 2, "staking delegate <validator> <amount>");
                let amt = require(&pos, 3, "staking delegate <validator> <amount>");
                print_staking_tx_help(
                    "delegate",
                    &format!("{val} {amt}"),
                    &format!("stake delegate {val} {amt}"),
                );
            }
            Some("undelegate") => {
                let val = require(&pos, 2, "staking undelegate <validator> <amount>");
                let amt = require(&pos, 3, "staking undelegate <validator> <amount>");
                print_staking_tx_help(
                    "undelegate",
                    &format!("{val} {amt}"),
                    &format!("stake undelegate {val} {amt}"),
                );
            }
            Some("withdraw") => {
                let val = require(&pos, 2, "staking withdraw <validator>");
                print_staking_tx_help("withdraw", &val, &format!("stake withdraw {val}"));
            }
            Some("register") => {
                let commission = require(&pos, 2, "staking register <commission_bps>");
                print_staking_tx_help(
                    "register",
                    &commission,
                    &format!("stake register {commission}"),
                );
            }
            Some("deregister") => {
                print_staking_tx_help("deregister", "", "stake deregister");
            }
            Some(sub) => {
                eprintln!("Unknown staking subcommand: {sub}");
                eprintln!("Usage: staking <info|delegate|undelegate|withdraw|register|deregister>");
                process::exit(1);
            }
        },

        Some("gov") => match pos.get(1).map(|s| s.as_str()) {
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
        },

        Some("faucet") => {
            let addr = require(&pos, 1, "faucet <address> <amount>");
            let amount = require(&pos, 2, "faucet <address> <amount>");
            cmd_faucet(&rpc, &addr, &amount);
        }

        Some("vm") => match pos.get(1).map(String::as_str) {
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
        },

        Some("doctor") => {
            let data_dir = pos.get(1).map(|s| s.as_str()).unwrap_or("./data");
            cmd_doctor(&rpc, data_dir);
        }

        Some("upgrade") => match pos.get(1).map(|s| s.as_str()) {
            Some("check") | None => cmd_upgrade_check(&rpc),
            Some("apply") => {
                let version = require(&pos, 2, "upgrade apply <version>");
                cmd_upgrade_apply(&version);
            }
            _ => {
                eprintln!("Usage: upgrade [check | apply <version>]");
                process::exit(1);
            }
        },

        Some("backup") => {
            let data_dir = pos.get(1).map(|s| s.as_str()).unwrap_or("./data");
            let output = pos.get(2).map(|s| s.as_str()).unwrap_or("./backup");
            cmd_backup(data_dir, output);
        }

        Some("restore") => {
            let backup_path = require(&pos, 1, "restore <backup-path> [data-dir]");
            let data_dir = pos.get(2).map(|s| s.as_str()).unwrap_or("./data");
            cmd_restore(&backup_path, data_dir);
        }

        Some("keys") => match pos.get(1).map(|s| s.as_str()) {
            Some("check") | None => {
                let data_dir = pos.get(2).map(|s| s.as_str()).unwrap_or("./data");
                cmd_keys_check(data_dir);
            }
            _ => {
                eprintln!("Usage: keys check [data-dir]");
                process::exit(1);
            }
        },

        Some("cert") => {
            match pos.get(1).map(|s| s.as_str()) {
                Some("rotate") => {
                    let data_dir = pos.get(2).map(|s| s.as_str()).unwrap_or("./data");
                    let days: u32 = pos.get(3).and_then(|s| s.parse().ok()).unwrap_or(365);
                    cmd_cert_rotate(data_dir, days);
                }
                Some("reload") | None => {
                    // Hot-reload via admin RPC: POST /admin/cert/reload
                    // Triggers CertReloader::reload() in the running node (zero downtime).
                    cmd_cert_reload(&rpc);
                }
                Some("status") => {
                    // Show current cert info via admin RPC: GET /admin/cert/status
                    cmd_cert_status_rpc(&rpc);
                }
                _ => {
                    eprintln!("Usage: cert <subcommand>");
                    eprintln!("  cert reload              Hot-reload cert via running node (SIGHUP equivalent)");
                    eprintln!(
                        "  cert status              Show current cert subject, expiry, fingerprint"
                    );
                    eprintln!("  cert rotate [dir] [days] Generate new cert + reload in one step");
                    process::exit(1);
                }
            }
        }

        Some("support-bundle") => {
            let data_dir = pos.get(1).map(|s| s.as_str()).unwrap_or("./data");
            let output = pos
                .get(2)
                .map(|s| s.as_str())
                .unwrap_or("./iona-support-bundle.tar.gz");
            cmd_support_bundle(&rpc, data_dir, output);
        }

        Some("rbac") => match pos.get(1).map(|s| s.as_str()) {
            Some("check") => {
                let identity = require(&pos, 2, "rbac check <identity> <endpoint>");
                let endpoint = require(&pos, 3, "rbac check <identity> <endpoint>");
                cmd_rbac_check(&rpc, &identity, &endpoint);
            }
            Some("export") => {
                let data_dir = pos.get(2).map(|s| s.as_str()).unwrap_or("./data");
                cmd_rbac_export(data_dir);
            }
            _ => {
                eprintln!("Usage: rbac [check <identity> <endpoint> | export [data-dir]]");
                process::exit(1);
            }
        },

        Some("audit") => match pos.get(1).map(|s| s.as_str()) {
            Some("verify") => {
                let path = require(&pos, 2, "audit verify <path>");
                cmd_audit_verify(&path);
            }
            Some("export") => {
                let path = require(&pos, 2, "audit export <path> [--last N]");
                let last_n: usize = pos
                    .windows(2)
                    .find(|w| w[0] == "--last")
                    .and_then(|w| w[1].parse().ok())
                    .unwrap_or(100);
                cmd_audit_export(&path, last_n);
            }
            Some("tail") => {
                let path = require(&pos, 2, "audit tail <path> [--follow]");
                let follow = pos.iter().any(|s| s == "--follow" || s == "-f");
                cmd_audit_tail(&path, follow);
            }
            _ => {
                eprintln!("Usage: audit [verify <path> | export <path> [--last N] | tail <path> [--follow]]");
                process::exit(1);
            }
        },

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
        Ok(v) => print_json(&v),
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
        Ok(r) => match r.into_json::<serde_json::Value>() {
            Ok(v) => print_json(&v),
            Err(e) => die(&format!("JSON decode error: {e}")),
        },
        Err(e) => die(&format!("HTTP error: {e}")),
    }
}

// ── Audit commands (v28.2) ────────────────────────────────────────────────

/// Verify the tamper-evident hashchain in the given audit log file.
///
/// Usage: iona-cli audit verify <path>
///
/// Exit codes: 0 = chain intact, 1 = broken/error.
fn cmd_audit_verify(path: &str) {
    use iona::audit::verify_hashchain;
    use iona::audit::VerifyResult;

    let result = match verify_hashchain(std::path::Path::new(path)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error reading '{path}': {e}");
            std::process::exit(1);
        }
    };

    println!("{result}");
    if matches!(result, VerifyResult::Broken { .. }) {
        std::process::exit(1);
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

// ── iona doctor ───────────────────────────────────────────────────────────
//
// Runs a series of diagnostic checks and reports pass/fail for each.

/// ANSI helpers (no external deps required)
fn green(s: &str) -> String {
    format!("\x1b[32m{s}\x1b[0m")
}
fn red(s: &str) -> String {
    format!("\x1b[31m{s}\x1b[0m")
}
fn yellow(s: &str) -> String {
    format!("\x1b[33m{s}\x1b[0m")
}

fn pass(label: &str, detail: &str) {
    println!("  {} {label}: {detail}", green("PASS"));
}
fn fail(label: &str, detail: &str) {
    println!("  {} {label}: {detail}", red("FAIL"));
}
fn warn(label: &str, detail: &str) {
    println!("  {} {label}: {detail}", yellow("WARN"));
}

fn cmd_doctor(rpc: &str, data_dir: &str) {
    use std::net::TcpListener;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    println!("\n╔══════════════════════════════════════╗");
    println!("║       IONA Node Diagnostics          ║");
    println!("╚══════════════════════════════════════╝\n");

    let mut failures = 0usize;
    let mut warnings = 0usize;

    // ── 1. Node reachability ──────────────────────────────────────────────
    println!("[ 1 ] Node reachability");
    let health_url = format!("{rpc}/health");
    match ureq::get(&health_url)
        .timeout(std::time::Duration::from_secs(3))
        .call()
    {
        Ok(resp) if resp.status() == 200 => pass("RPC health", &format!("{rpc}/health → 200 OK")),
        Ok(resp) => {
            fail("RPC health", &format!("HTTP {}", resp.status()));
            failures += 1;
        }
        Err(e) => {
            fail("RPC health", &format!("unreachable: {e}"));
            failures += 1;
        }
    }

    // ── 2. Peer count ─────────────────────────────────────────────────────
    println!("\n[ 2 ] Peer count");
    match ureq::get(&format!("{rpc}/status"))
        .timeout(std::time::Duration::from_secs(3))
        .call()
    {
        Ok(resp) => {
            if let Ok(v) = resp.into_json::<serde_json::Value>() {
                let peers = v.get("peers").and_then(|p| p.as_u64()).unwrap_or(0);
                if peers >= 5 {
                    pass("Peer count", &format!("{peers} peers connected"));
                } else if peers >= 3 {
                    warn(
                        "Peer count",
                        &format!("{peers} peers — below recommended 5"),
                    );
                    warnings += 1;
                } else {
                    fail("Peer count", &format!("{peers} peers — CRITICAL (< 3)"));
                    failures += 1;
                }
            }
        }
        Err(_) => {
            warn(
                "Peer count",
                "could not fetch status (node may be starting)",
            );
            warnings += 1;
        }
    }

    // ── 3. Ports ──────────────────────────────────────────────────────────
    println!("\n[ 3 ] Port availability (local check)");
    let ports: &[(&str, u16)] = &[
        ("P2P", 7001),
        ("RPC", 9001),
        ("Admin", 9002),
        ("Prom", 9090),
    ];
    for (name, port) in ports {
        // Try binding — if we can bind, nobody is listening (port is free).
        // If bind fails, something is already listening (expected for a running node).
        match TcpListener::bind(format!("127.0.0.1:{port}")) {
            Ok(_) => warn(
                name,
                &format!("port {port} is free — node may not be running"),
            ),
            Err(_) => pass(
                name,
                &format!("port {port} in use (expected for running node)"),
            ),
        }
    }

    // ── 4. Disk space ─────────────────────────────────────────────────────
    println!("\n[ 4 ] Disk space");
    let data_path = Path::new(data_dir);
    if data_path.exists() {
        // Use statvfs via libc — fallback to reading /proc/mounts on Linux
        #[cfg(target_os = "linux")]
        {
            use std::mem::MaybeUninit;
            let path_cstr = std::ffi::CString::new(data_dir).unwrap_or_default();
            let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
            unsafe {
                if libc::statvfs(path_cstr.as_ptr(), stat.as_mut_ptr()) == 0 {
                    let stat = stat.assume_init();
                    let free_bytes = stat.f_bavail as u64 * stat.f_frsize as u64;
                    let total_bytes = stat.f_blocks as u64 * stat.f_frsize as u64;
                    let pct_free = free_bytes * 100 / total_bytes.max(1);
                    let free_gib = free_bytes / (1024 * 1024 * 1024);
                    if pct_free >= 20 {
                        pass("Disk space", &format!("{free_gib} GiB free ({pct_free}%)"));
                    } else if pct_free >= 10 {
                        warn(
                            "Disk space",
                            &format!("{free_gib} GiB free ({pct_free}%) — below 20%"),
                        );
                        warnings += 1;
                    } else {
                        fail(
                            "Disk space",
                            &format!("{free_gib} GiB free ({pct_free}%) — CRITICAL"),
                        );
                        failures += 1;
                    }
                } else {
                    warn("Disk space", "statvfs failed — cannot check");
                    warnings += 1;
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            pass(
                "Disk space",
                &format!("data dir exists: {data_dir} (space check requires Linux)"),
            );
        }
    } else {
        fail(
            "Disk space",
            &format!("data dir does not exist: {data_dir}"),
        );
        failures += 1;
    }

    // ── 5. Key file permissions ───────────────────────────────────────────
    println!("\n[ 5 ] Key file permissions");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let key_files = [
            (format!("{data_dir}/keys.enc"), 0o600u32),
            (format!("{data_dir}/keys.json"), 0o600u32),
            (format!("{data_dir}/node_key.json"), 0o600u32),
        ];
        let mut any_key = false;
        for (path, expected_mode) in &key_files {
            let p = Path::new(path);
            if !p.exists() {
                continue;
            }
            any_key = true;
            if let Ok(meta) = std::fs::metadata(p) {
                let mode = meta.mode() & 0o777;
                if mode == *expected_mode {
                    pass("Key perms", &format!("{path}: 0{mode:03o} ✓"));
                } else {
                    fail(
                        "Key perms",
                        &format!("{path}: 0{mode:03o} (expected 0{expected_mode:03o})"),
                    );
                    failures += 1;
                }
            }
        }
        if !any_key {
            warn(
                "Key files",
                "no key files found in data dir (node may not be initialized)",
            );
            warnings += 1;
        }

        // Data dir itself
        if let Ok(meta) = std::fs::metadata(data_dir) {
            let mode = meta.mode() & 0o777;
            if mode <= 0o700 {
                pass("Data dir perms", &format!("{data_dir}: 0{mode:03o} ✓"));
            } else {
                warn(
                    "Data dir perms",
                    &format!("{data_dir}: 0{mode:03o} — should be 0700 or stricter"),
                );
                warnings += 1;
            }
        }
    }
    #[cfg(not(unix))]
    {
        pass("Key file permissions", "permission check requires Unix");
    }

    // ── 6. Time drift ─────────────────────────────────────────────────────
    println!("\n[ 6 ] System time (NTP drift check)");
    // Compare local time to node-reported time. A drift > 2s is problematic for BFT consensus.
    let local_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match ureq::get(&format!("{rpc}/status"))
        .timeout(std::time::Duration::from_secs(3))
        .call()
    {
        Ok(resp) => {
            if let Ok(v) = resp.into_json::<serde_json::Value>() {
                let node_ts = v
                    .get("block_time")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(local_ts);
                let drift = (local_ts as i64 - node_ts as i64).abs();
                if drift <= 2 {
                    pass(
                        "Time drift",
                        &format!("{drift}s (local vs last block time)"),
                    );
                } else if drift <= 10 {
                    warn(
                        "Time drift",
                        &format!("{drift}s — above 2s (check NTP sync)"),
                    );
                    warnings += 1;
                } else {
                    fail(
                        "Time drift",
                        &format!("{drift}s — CRITICAL (BFT requires < 2s)"),
                    );
                    failures += 1;
                }
            }
        }
        Err(_) => {
            pass("Time drift", "cannot check (node not responding — skipped)");
        }
    }

    // ── 7. Double-sign guard ──────────────────────────────────────────────
    println!("\n[ 7 ] Double-sign guard");
    let wal_path = format!("{data_dir}/signing.wal");
    if Path::new(&wal_path).exists() {
        pass(
            "Signing WAL",
            &format!("{wal_path} present — double-sign protection active"),
        );
    } else {
        warn(
            "Signing WAL",
            &format!("{wal_path} not found — will be created on first sign"),
        );
        warnings += 1;
    }

    // ── Summary ───────────────────────────────────────────────────────────
    println!("\n══════════════════════════════════════════");
    if failures == 0 && warnings == 0 {
        println!("  {} All checks passed!", green("✓"));
    } else {
        if failures > 0 {
            println!("  {} {failures} failure(s)", red("✗"));
        }
        if warnings > 0 {
            println!("  {} {warnings} warning(s)", yellow("⚠"));
        }
    }
    println!("══════════════════════════════════════════\n");

    if failures > 0 {
        process::exit(1);
    }
}

// ── iona upgrade ──────────────────────────────────────────────────────────

/// Check if a newer version is available.
fn cmd_upgrade_check(rpc: &str) {
    println!("\n╔══════════════════════════════════════╗");
    println!("║       IONA Upgrade Check             ║");
    println!("╚══════════════════════════════════════╝\n");

    // Get current running version from the node
    let current_version = match ureq::get(&format!("{rpc}/status"))
        .timeout(std::time::Duration::from_secs(3))
        .call()
    {
        Ok(resp) => resp
            .into_json::<serde_json::Value>()
            .ok()
            .and_then(|v| {
                v.get("version")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "unknown".to_string()),
        Err(_) => "unknown (node not reachable)".to_string(),
    };

    println!("  Running version  : {current_version}");

    // Check GitHub releases API for latest version
    match ureq::get("https://api.github.com/repos/your-org/iona/releases/latest")
        .set("User-Agent", "iona-cli/28.3")
        .timeout(std::time::Duration::from_secs(5))
        .call()
    {
        Ok(resp) => {
            if let Ok(v) = resp.into_json::<serde_json::Value>() {
                let latest = v
                    .get("tag_name")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                println!("  Latest version   : {latest}");
                if current_version.contains(latest.trim_start_matches('v')) {
                    println!("\n  {} You are running the latest version.", green("✓"));
                } else {
                    println!("\n  {} Upgrade available: {latest}", yellow("↑"));
                    println!("\n  To upgrade safely, run:");
                    println!("    scripts/upgrade.sh {latest}");
                    println!("  Or use --dry-run first:");
                    println!("    scripts/upgrade.sh --dry-run {latest}");
                    println!("\n  Full upgrade guidance: docs/UPGRADE.md");
                }
            }
        }
        Err(_) => {
            println!("  Latest version   : (could not reach GitHub)");
            println!("\n  Check https://github.com/your-org/iona/releases for the latest release.");
            println!("  Upgrade script: scripts/upgrade.sh <version>");
        }
    }

    println!("\n  Pre-upgrade checklist:");
    println!("    1. Run: iona doctor (all checks must pass)");
    println!("    2. Run: iona backup ./data ./backup-$(date +%Y%m%d)");
    println!("    3. Run: iona-node --dry-run-migrations --config config.toml");
    println!("    4. Review CHANGELOG.md for breaking changes");
    println!("    5. Run: scripts/upgrade.sh <target-version>");
    println!();
}

/// Guided upgrade apply command.
fn cmd_upgrade_apply(version: &str) {
    println!("\n╔══════════════════════════════════════╗");
    println!("║       IONA Upgrade Apply             ║");
    println!("╚══════════════════════════════════════╝\n");
    println!("  Target version: {version}");
    println!();
    println!("  The interactive upgrade is handled by scripts/upgrade.sh.");
    println!("  This command provides a guided checklist:\n");

    let steps = [
        ("Stop scheduling new transactions",    "Notify users / load balancer"),
        ("Create backup",                        "iona backup ./data ./backup-pre-upgrade"),
        ("Verify backup",                        "ls -lh ./backup-pre-upgrade/"),
        ("Download new binary",                  &format!("curl -LO https://github.com/your-org/iona/releases/download/{version}/iona-{version}.tar.gz")),
        ("Verify signature",                     &format!("cosign verify-blob --key cosign.pub iona-{version}.tar.gz")),
        ("Run compatibility check",              "iona-node --check-compat --config config.toml"),
        ("Run dry-run migrations",               "iona-node --dry-run-migrations --config config.toml"),
        ("Stop node",                            "systemctl stop iona-node"),
        ("Replace binary",                       &format!("cp iona-node /usr/local/bin/iona-node")),
        ("Start node",                           "systemctl start iona-node"),
        ("Verify node health",                   "iona doctor"),
        ("Watch logs for 5 minutes",             "journalctl -fu iona-node | head -100"),
    ];

    for (i, (step, cmd)) in steps.iter().enumerate() {
        println!("  [ {} ] {step}", i + 1);
        println!("         Command: {cmd}");
        println!();
    }

    println!("  Rollback (if something goes wrong):");
    println!("    systemctl stop iona-node");
    println!("    iona restore ./backup-pre-upgrade ./data");
    println!("    cp iona-node-OLD /usr/local/bin/iona-node");
    println!("    systemctl start iona-node");
    println!("    iona doctor");
    println!();
    println!("  For automated upgrade: scripts/upgrade.sh {version}");
    println!();
}

// ── iona backup ───────────────────────────────────────────────────────────

fn cmd_backup(data_dir: &str, output_dir: &str) {
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup_name = format!("iona-backup-{ts}");
    let backup_path = format!("{output_dir}/{backup_name}.tar.gz");

    println!("\n╔══════════════════════════════════════╗");
    println!("║       IONA Backup                    ║");
    println!("╚══════════════════════════════════════╝\n");

    if !Path::new(data_dir).exists() {
        eprintln!("  {} Data directory not found: {data_dir}", red("FAIL"));
        process::exit(1);
    }

    // Create output directory
    if let Err(e) = std::fs::create_dir_all(output_dir) {
        eprintln!(
            "  {} Cannot create output dir {output_dir}: {e}",
            red("FAIL")
        );
        process::exit(1);
    }

    println!("  Source      : {data_dir}");
    println!("  Destination : {backup_path}");
    println!("  Timestamp   : {ts}");
    println!();

    // Use tar via std::process::Command
    let status = std::process::Command::new("tar")
        .args([
            "czf",
            &backup_path,
            "--exclude=*.log", // skip log files (can be large, not needed for restore)
            "--exclude=*/wal/*.tmp", // skip temporary WAL files
            "-C",
            data_dir,
            ".",
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            if let Ok(meta) = std::fs::metadata(&backup_path) {
                let size_mb = meta.len() / (1024 * 1024);
                println!(
                    "  {} Backup created: {backup_path} ({size_mb} MiB)",
                    green("✓")
                );
            } else {
                println!("  {} Backup created: {backup_path}", green("✓"));
            }
            println!();
            println!("  Key backup policy:");
            println!("    • Verify backup integrity: tar tzf {backup_path}");
            println!("    • Store keys.enc backup separately (encrypted, offline)");
            println!("    • Test restore on a non-production machine periodically");
            println!("    • Never store backup on the same machine as the validator");
        }
        Ok(s) => {
            eprintln!("  {} tar exited with code {:?}", red("FAIL"), s.code());
            process::exit(1);
        }
        Err(e) => {
            eprintln!("  {} Could not run tar: {e}", red("FAIL"));
            eprintln!("  Ensure tar is installed: apt install tar");
            process::exit(1);
        }
    }
    println!();
}

// ── iona restore ──────────────────────────────────────────────────────────

fn cmd_restore(backup_path: &str, data_dir: &str) {
    use std::path::Path;

    println!("\n╔══════════════════════════════════════╗");
    println!("║       IONA Restore                   ║");
    println!("╚══════════════════════════════════════╝\n");

    if !Path::new(backup_path).exists() {
        eprintln!("  {} Backup file not found: {backup_path}", red("FAIL"));
        process::exit(1);
    }

    println!(
        "  {} RESTORE WILL OVERWRITE: {data_dir}",
        yellow("⚠  WARNING")
    );
    println!("  Backup source: {backup_path}");
    println!();

    // Safety check: is the node running?
    if let Ok(resp) = ureq::get("http://127.0.0.1:9001/health")
        .timeout(std::time::Duration::from_secs(1))
        .call()
    {
        if resp.status() == 200 {
            eprintln!(
                "  {} Node appears to be running (port 9001 is responding).",
                red("FAIL")
            );
            eprintln!("  Stop the node before restoring: systemctl stop iona-node");
            process::exit(1);
        }
    }

    println!("  Node is not running. Proceeding with restore...");
    println!();

    // Create data_dir if needed
    if let Err(e) = std::fs::create_dir_all(data_dir) {
        eprintln!("  {} Cannot create data dir {data_dir}: {e}", red("FAIL"));
        process::exit(1);
    }

    let status = std::process::Command::new("tar")
        .args(["xzf", backup_path, "-C", data_dir, "--strip-components=1"])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!(
                "  {} Restore complete: {backup_path} → {data_dir}",
                green("✓")
            );
            println!();
            println!("  Next steps:");
            println!("    1. Verify data: ls -la {data_dir}");
            println!("    2. Check keys:  iona keys check {data_dir}");
            println!("    3. Start node:  systemctl start iona-node");
            println!("    4. Run doctor:  iona doctor");
        }
        Ok(s) => {
            eprintln!("  {} tar exited with code {:?}", red("FAIL"), s.code());
            process::exit(1);
        }
        Err(e) => {
            eprintln!("  {} Could not run tar: {e}", red("FAIL"));
            process::exit(1);
        }
    }
    println!();
}

// ── iona keys check ───────────────────────────────────────────────────────

fn cmd_keys_check(data_dir: &str) {
    use std::path::Path;

    println!("\n╔══════════════════════════════════════╗");
    println!("║       IONA Key Check                 ║");
    println!("╚══════════════════════════════════════╝\n");
    println!("  Data directory: {data_dir}\n");

    let mut failures = 0usize;
    let mut warnings = 0usize;
    let mut found = 0usize;

    // ── Key files to check ────────────────────────────────────────────────
    let key_entries: &[(&str, &str, u32)] = &[
        ("keys.enc", "Validator signing key (encrypted)", 0o600),
        (
            "keys.json",
            "Validator signing key (plaintext — should be replaced with keys.enc)",
            0o600,
        ),
        ("node_key.json", "P2P node identity key", 0o600),
    ];

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        for (filename, description, expected_mode) in key_entries {
            let path = format!("{data_dir}/{filename}");
            let p = Path::new(&path);

            if !p.exists() {
                // Warn for optional files, fail for required ones
                if *filename == "keys.enc" {
                    warn(
                        "keys.enc",
                        &format!("not found at {path} (node may not be initialized)"),
                    );
                    warnings += 1;
                }
                continue;
            }
            found += 1;

            match std::fs::metadata(p) {
                Ok(meta) => {
                    let mode = meta.mode() & 0o777;
                    if mode == *expected_mode {
                        pass(filename, &format!("{description} — perms 0{mode:03o} ✓"));
                    } else if mode & 0o077 != 0 {
                        fail(filename, &format!("{description} — perms 0{mode:03o} (expected 0{expected_mode:03o}); group/world readable!"));
                        failures += 1;
                    } else {
                        warn(filename, &format!("{description} — perms 0{mode:03o} (recommended 0{expected_mode:03o})"));
                        warnings += 1;
                    }

                    // Warn if keys.json exists alongside keys.enc (plaintext backup risk)
                    if *filename == "keys.json" {
                        warn("keys.json", "plaintext key file present. Consider removing after converting to keys.enc");
                        warnings += 1;
                    }
                }
                Err(e) => {
                    fail(filename, &format!("cannot stat {path}: {e}"));
                    failures += 1;
                }
            }
        }

        // ── Data directory itself ─────────────────────────────────────────
        if Path::new(data_dir).exists() {
            if let Ok(meta) = std::fs::metadata(data_dir) {
                let mode = meta.mode() & 0o777;
                if mode & 0o077 == 0 {
                    pass(
                        "data dir",
                        &format!("0{mode:03o} (no group/world access) ✓"),
                    );
                } else if mode & 0o007 != 0 {
                    fail(
                        "data dir",
                        &format!("0{mode:03o} — world-readable!  Run: chmod 700 {data_dir}"),
                    );
                    failures += 1;
                } else {
                    warn(
                        "data dir",
                        &format!("0{mode:03o} — group-readable. Recommended: chmod 700 {data_dir}"),
                    );
                    warnings += 1;
                }
            }
        } else {
            fail("data dir", &format!("{data_dir} does not exist"));
            failures += 1;
        }
    }
    #[cfg(not(unix))]
    {
        pass("permissions", "Unix permission check skipped on this OS");
    }

    // ── Signing WAL ────────────────────────────────────────────────────────
    println!();
    let wal_path = format!("{data_dir}/signing.wal");
    if Path::new(&wal_path).exists() {
        pass("signing.wal", "double-sign protection WAL present ✓");
        found += 1;
    } else {
        warn(
            "signing.wal",
            "not found — will be created on first block signing",
        );
        warnings += 1;
    }

    // ── TLS cert expiry (admin mTLS) ──────────────────────────────────────
    println!();
    let cert_paths = [
        format!("{data_dir}/../tls/admin.crt.pem"),
        "./tls/admin.crt.pem".to_string(),
        "/etc/iona/tls/admin.crt.pem".to_string(),
    ];
    let mut cert_checked = false;
    for cert_path in &cert_paths {
        if !Path::new(cert_path).exists() {
            continue;
        }
        cert_checked = true;
        // Use openssl to check expiry (external command)
        let output = std::process::Command::new("openssl")
            .args(["x509", "-noout", "-enddate", "-in", cert_path])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                let expiry = String::from_utf8_lossy(&o.stdout).trim().to_string();
                pass("admin cert", &format!("{cert_path} — {expiry}"));
            }
            Ok(_) => {
                warn(
                    "admin cert",
                    &format!("{cert_path} — could not parse (openssl error)"),
                );
                warnings += 1;
            }
            Err(_) => {
                warn(
                    "admin cert",
                    "openssl not available — cannot check cert expiry",
                );
                warnings += 1;
            }
        }
        break;
    }
    if !cert_checked {
        warn(
            "admin cert",
            "no admin TLS cert found — mTLS admin port may not be configured",
        );
        warnings += 1;
    }

    // ── Summary ──────────────────────────────────────────────────────────
    println!("\n══════════════════════════════════════════");
    println!("  Key files found: {found}");
    if failures == 0 && warnings == 0 {
        println!("  {} All key checks passed!", green("✓"));
    } else {
        if failures > 0 {
            println!(
                "  {} {failures} failure(s) — fix before running as validator",
                red("✗")
            );
        }
        if warnings > 0 {
            println!("  {} {warnings} warning(s)", yellow("⚠"));
        }
    }
    println!("══════════════════════════════════════════\n");

    if failures > 0 {
        process::exit(1);
    }
}

// ── iona cert rotate ──────────────────────────────────────────────────────
//
// Generates a fresh self-signed TLS certificate for the admin mTLS interface.
// The existing cert is backed up, the new cert is written in-place, and the
// admin server is signalled to hot-reload via SIGHUP.

fn cert_dir(data_dir: &str) -> String {
    let candidate = format!("{data_dir}/../tls");
    if std::path::Path::new(&candidate).exists() {
        candidate
    } else {
        "/etc/iona/tls".to_string()
    }
}

fn cmd_cert_rotate(data_dir: &str, days: u32) {
    use std::path::Path;

    println!("\n╔══════════════════════════════════════╗");
    println!("║       IONA Cert Rotation             ║");
    println!("╚══════════════════════════════════════╝\n");

    let tls_dir = cert_dir(data_dir);
    let cert_path = format!("{tls_dir}/admin.crt.pem");
    let key_path = format!("{tls_dir}/admin.key.pem");
    let ca_path = format!("{tls_dir}/ca.crt.pem");

    println!("  TLS directory : {tls_dir}");
    println!("  Validity      : {days} days\n");

    // ── Step 1: back up existing cert ────────────────────────────────────
    if Path::new(&cert_path).exists() {
        let backup = format!("{cert_path}.bak");
        match std::fs::copy(&cert_path, &backup) {
            Ok(_) => pass("Backup", &format!("{cert_path} → {backup}")),
            Err(e) => {
                eprintln!("  {} Cannot back up cert: {e}", red("FAIL"));
                process::exit(1);
            }
        }
    } else {
        warn("Backup", "no existing cert — generating fresh");
    }

    // ── Step 2: ensure TLS dir exists ────────────────────────────────────
    if let Err(e) = std::fs::create_dir_all(&tls_dir) {
        eprintln!("  {} Cannot create {tls_dir}: {e}", red("FAIL"));
        process::exit(1);
    }

    // ── Step 3: generate CA (if absent) ──────────────────────────────────
    let ca_key_path = format!("{tls_dir}/ca.key.pem");
    if !Path::new(&ca_path).exists() {
        println!("\n  Generating CA...");
        let r1 = std::process::Command::new("openssl")
            .args(["genrsa", "-out", &ca_key_path, "4096"])
            .status();
        let r2 = std::process::Command::new("openssl")
            .args([
                "req",
                "-new",
                "-x509",
                "-days",
                &days.to_string(),
                "-key",
                &ca_key_path,
                "-out",
                &ca_path,
                "-subj",
                "/CN=IONA-Admin-CA/O=IONA/OU=Validator",
            ])
            .status();
        match (r1, r2) {
            (Ok(s1), Ok(s2)) if s1.success() && s2.success() => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &ca_key_path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                pass("CA cert", &ca_path);
            }
            _ => {
                eprintln!("  {} openssl CA generation failed", red("FAIL"));
                process::exit(1);
            }
        }
    } else {
        pass("CA cert", &format!("{ca_path} (reusing)"));
    }

    // ── Step 4: generate server key + sign ───────────────────────────────
    let csr_path = format!("{tls_dir}/admin.csr.tmp");
    let r_key = std::process::Command::new("openssl")
        .args(["genrsa", "-out", &key_path, "4096"])
        .status();
    let r_csr = std::process::Command::new("openssl")
        .args([
            "req",
            "-new",
            "-key",
            &key_path,
            "-out",
            &csr_path,
            "-subj",
            "/CN=iona-admin/O=IONA/OU=Validator",
        ])
        .status();
    let r_sign = std::process::Command::new("openssl")
        .args([
            "x509",
            "-req",
            "-days",
            &days.to_string(),
            "-in",
            &csr_path,
            "-CA",
            &ca_path,
            "-CAkey",
            &ca_key_path,
            "-CAcreateserial",
            "-out",
            &cert_path,
        ])
        .status();
    let _ = std::fs::remove_file(&csr_path);

    match (r_key, r_csr, r_sign) {
        (Ok(s1), Ok(s2), Ok(s3)) if s1.success() && s2.success() && s3.success() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
            }
            pass("Server cert", &format!("{cert_path} ({days} days)"));
            pass("Server key", &format!("{key_path} (0600)"));
        }
        _ => {
            eprintln!("  {} Certificate signing failed", red("FAIL"));
            process::exit(1);
        }
    }

    // ── Step 5: signal hot-reload ─────────────────────────────────────────
    let pid_path = format!("{data_dir}/iona-node.pid");
    let mut reloaded = false;
    if Path::new(&pid_path).exists() {
        if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                #[cfg(unix)]
                unsafe {
                    if libc::kill(pid, libc::SIGHUP) == 0 {
                        pass("Hot-reload", &format!("SIGHUP → PID {pid}"));
                        reloaded = true;
                    }
                }
            }
        }
    }
    if !reloaded {
        warn(
            "Hot-reload",
            "PID file not found — restart node to activate new cert",
        );
    }

    println!("\n══════════════════════════════════════════");
    println!("  {} Certificate rotation complete!", green("✓"));
    println!("  Verify: iona cert status {data_dir}");
    println!("══════════════════════════════════════════\n");
}

fn cmd_cert_status(data_dir: &str) {
    use std::path::Path;

    println!("\n╔══════════════════════════════════════╗");
    println!("║       IONA Cert Status               ║");
    println!("╚══════════════════════════════════════╝\n");

    let tls_dir = cert_dir(data_dir);
    for (path, label) in &[
        (format!("{tls_dir}/admin.crt.pem"), "Admin cert"),
        (format!("{tls_dir}/ca.crt.pem"), "CA cert"),
    ] {
        if !Path::new(path).exists() {
            warn(label, &format!("{path} not found"));
            continue;
        }
        let output = std::process::Command::new("openssl")
            .args(["x509", "-noout", "-subject", "-enddate", "-in", path])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                for line in String::from_utf8_lossy(&o.stdout).lines() {
                    println!("  {label}: {}", line.trim());
                }
                pass(label, path);
            }
            _ => {
                warn(label, &format!("{path} — openssl parse error"));
            }
        }
        println!();
    }
}

// ── iona cert reload ──────────────────────────────────────────────────────
//
// Triggers hot-reload of the mTLS cert in the running node via admin RPC.
// Equivalent to: kill -HUP $(pidof iona-node)
// Requires admin RPC accessible + maintainer RBAC role.
//
// Admin RPC endpoint: POST /admin/cert/reload
// Returns: { ok, new_subject, new_fingerprint, expires_in_s, overlap_active }

fn cmd_cert_reload(rpc: &str) {
    println!("\n╔══════════════════════════════════════╗");
    println!("║      IONA Cert Hot-Reload            ║");
    println!("╚══════════════════════════════════════╝\n");

    let admin_url = if rpc.contains("/admin") {
        rpc.to_string()
    } else {
        format!("{}/admin/cert/reload", rpc.trim_end_matches('/'))
    };

    println!("  Sending reload request → {admin_url}");

    let output = std::process::Command::new("curl")
        .args([
            "-sf",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--max-time",
            "10",
            "--cert",
            "/etc/iona/tls/operator.crt",
            "--key",
            "/etc/iona/tls/operator.key",
            "--cacert",
            "/etc/iona/tls/ca.crt",
            &format!("{}/admin/cert/reload", rpc.trim_end_matches('/')),
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let body = String::from_utf8_lossy(&o.stdout);
            if body.contains("\"ok\":true") {
                println!("  ✓ Cert reloaded successfully\n");
                // Parse and display key fields
                for field in &[
                    "new_subject",
                    "new_fingerprint",
                    "expires_in_s",
                    "overlap_active",
                    "overlap_seconds",
                    "rotation_count",
                ] {
                    if let Some(val) = extract_json_field(&body, field) {
                        println!("    {field:20} {val}");
                    }
                }
                println!("\n  Old cert accepted for overlap window. No downtime.");
            } else {
                eprintln!("  ✗ Reload failed: {}", body.trim());
                // Suggest SIGHUP fallback
                eprintln!("\n  Fallback: systemctl reload iona-node");
                eprintln!("         or: kill -HUP $(pidof iona-node)");
                std::process::exit(1);
            }
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            eprintln!("  ✗ Admin RPC error ({}): {}", o.status, stderr.trim());
            eprintln!("\n  Tip: ensure mTLS cert at /etc/iona/tls/operator.crt is valid.");
            eprintln!("  Fallback: systemctl reload iona-node  (sends SIGHUP)");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("  ✗ curl not available: {e}");
            eprintln!("  Fallback: systemctl reload iona-node");
            std::process::exit(1);
        }
    }
}

// ── iona cert status (via admin RPC) ─────────────────────────────────────
//
// Shows live cert info from the running node.
// Admin RPC endpoint: GET /admin/cert/status
// Falls back to local openssl if RPC is unavailable.

fn cmd_cert_status_rpc(rpc: &str) {
    println!("\n╔══════════════════════════════════════╗");
    println!("║      IONA Cert Status (Live)         ║");
    println!("╚══════════════════════════════════════╝\n");

    let output = std::process::Command::new("curl")
        .args([
            "-sf",
            "-H",
            "Content-Type: application/json",
            "--max-time",
            "5",
            "--cert",
            "/etc/iona/tls/operator.crt",
            "--key",
            "/etc/iona/tls/operator.key",
            "--cacert",
            "/etc/iona/tls/ca.crt",
            &format!("{}/admin/cert/status", rpc.trim_end_matches('/')),
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let body = String::from_utf8_lossy(&o.stdout);
            println!("  Current certificate:");
            for field in &[
                "subject_cn",
                "fingerprint",
                "expires_in_s",
                "not_after_unix",
            ] {
                if let Some(val) = extract_json_field(&body, field) {
                    println!("    {field:20} {val}");
                }
            }
            if body.contains("\"overlap\":") && !body.contains("\"overlap\":null") {
                println!("\n  Overlap certificate (still accepted):");
                // overlap is a nested object — simplified display
                println!(
                    "    {}",
                    body.lines()
                        .find(|l| l.contains("overlap"))
                        .unwrap_or("    (parsing details — check raw JSON)")
                );
            }
            for field in &["rotation_count", "overlap_seconds", "watch_active"] {
                if let Some(val) = extract_json_field(&body, field) {
                    println!("    {field:20} {val}");
                }
            }
            println!();
        }
        _ => {
            eprintln!("  Admin RPC unavailable — showing local cert files:\n");
            // Fallback to local openssl
            for path in &["/etc/iona/tls/admin-server.crt", "/etc/iona/tls/ca.crt"] {
                let res = std::process::Command::new("openssl")
                    .args([
                        "x509",
                        "-noout",
                        "-subject",
                        "-enddate",
                        "-fingerprint",
                        "-sha256",
                        "-in",
                        path,
                    ])
                    .output();
                if let Ok(o) = res {
                    println!("  {}:", path);
                    for line in String::from_utf8_lossy(&o.stdout).lines() {
                        println!("    {}", line.trim());
                    }
                    println!();
                } else {
                    println!("  {path}: not found or not readable");
                }
            }
        }
    }
}

fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let needle = format!("\"{}\":", field);
    let pos = json.find(&needle)?;
    let rest = &json[pos + needle.len()..].trim_start();
    if rest.starts_with('"') {
        let end = rest[1..].find('"').unwrap_or(rest.len());
        Some(rest[1..end + 1].to_string())
    } else {
        let end = rest.find([',', '}', '\n']).unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

// ── iona support-bundle ───────────────────────────────────────────────────
//
// Collects a self-contained diagnostic archive for support or incident review:
//   - sanitized config (secrets redacted)
//   - last 500 lines of audit log
//   - live node status + peer list
//   - Prometheus metrics snapshot (iona_* only)
//   - system environment (uname, uptime, memory, disk)
//   - MANIFEST.txt listing all included files
fn cmd_support_bundle(rpc: &str, data_dir: &str, output_path: &str) {
    use std::path::Path;

    println!("\n╔══════════════════════════════════════╗");
    println!("║       IONA Support Bundle            ║");
    println!("╚══════════════════════════════════════╝\n");

    let bundle_dir = format!("/tmp/iona-support-{}", std::process::id());
    let _ = std::fs::create_dir_all(&bundle_dir);
    let mut manifest: Vec<String> = Vec::new();

    // ── Version + node status ─────────────────────────────────────────────
    println!("  Collecting version info...");
    let version_info = format!(
        "iona-cli: {}\nOS: {}/{}\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let _ = std::fs::write(format!("{bundle_dir}/version.txt"), &version_info);
    manifest.push("version.txt".into());

    if let Ok(resp) = ureq::get(&format!("{rpc}/status"))
        .timeout(std::time::Duration::from_secs(3))
        .call()
    {
        if let Ok(v) = resp.into_json::<serde_json::Value>() {
            let _ = std::fs::write(
                format!("{bundle_dir}/node-status.json"),
                serde_json::to_string_pretty(&v).unwrap_or_default(),
            );
            manifest.push("node-status.json".into());
        }
    }

    // ── Sanitized config ──────────────────────────────────────────────────
    println!("  Collecting config (sanitized)...");
    for config_path in &[
        format!("{data_dir}/../config.toml"),
        "/etc/iona/config.toml".into(),
        "./config.toml".into(),
    ] {
        if !Path::new(config_path.as_str()).exists() {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(config_path) {
            let sanitized: String = content
                .lines()
                .map(|line| {
                    let lower = line.to_lowercase();
                    if lower.contains("secret")
                        || lower.contains("password")
                        || lower.contains("token")
                        || lower.contains("private_key")
                    {
                        format!(
                            "{} = \"[REDACTED]\"",
                            line.split('=').next().unwrap_or(line).trim()
                        )
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let _ = std::fs::write(format!("{bundle_dir}/config.sanitized.toml"), sanitized);
            manifest.push("config.sanitized.toml".into());
            break;
        }
    }

    // ── Audit log tail ────────────────────────────────────────────────────
    println!("  Collecting audit log (last 500 lines)...");
    for audit_path in &[
        format!("{data_dir}/audit.log"),
        "/var/lib/iona/audit.log".into(),
    ] {
        if !Path::new(audit_path.as_str()).exists() {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(audit_path) {
            let lines: Vec<&str> = content.lines().collect();
            let tail = lines[lines.len().saturating_sub(500)..].join("\n");
            let _ = std::fs::write(format!("{bundle_dir}/audit.log.tail"), tail);
            manifest.push("audit.log.tail".into());
            break;
        }
    }

    // ── Peers ─────────────────────────────────────────────────────────────
    println!("  Collecting peer list...");
    if let Ok(resp) = ureq::get(&format!("{rpc}/peers"))
        .timeout(std::time::Duration::from_secs(3))
        .call()
    {
        if let Ok(v) = resp.into_json::<serde_json::Value>() {
            let _ = std::fs::write(
                format!("{bundle_dir}/peers.json"),
                serde_json::to_string_pretty(&v).unwrap_or_default(),
            );
            manifest.push("peers.json".into());
        }
    }

    // ── Metrics snapshot (iona_* only) ────────────────────────────────────
    println!("  Collecting Prometheus metrics...");
    if let Ok(resp) = ureq::get("http://127.0.0.1:9090/metrics")
        .timeout(std::time::Duration::from_secs(3))
        .call()
    {
        if let Ok(text) = resp.into_string() {
            let filtered = text
                .lines()
                .filter(|l| {
                    l.starts_with("iona_")
                        || l.starts_with("# HELP iona_")
                        || l.starts_with("# TYPE iona_")
                })
                .collect::<Vec<_>>()
                .join("\n");
            let _ = std::fs::write(format!("{bundle_dir}/metrics.txt"), filtered);
            manifest.push("metrics.txt (iona_* filtered)".into());
        }
    }

    // ── System environment ────────────────────────────────────────────────
    println!("  Collecting system info...");
    {
        let mut sysinfo = String::new();
        for (cmd, args) in &[
            ("uname", vec!["-a"]),
            ("uptime", vec![]),
            ("free", vec!["-h"]),
        ] {
            if let Ok(o) = std::process::Command::new(cmd)
                .args(args.as_slice())
                .output()
            {
                sysinfo.push_str(&format!("{cmd}:\n{}\n", String::from_utf8_lossy(&o.stdout)));
            }
        }
        if let Ok(o) = std::process::Command::new("df")
            .args(["-h", data_dir])
            .output()
        {
            sysinfo.push_str(&format!(
                "df {data_dir}:\n{}\n",
                String::from_utf8_lossy(&o.stdout)
            ));
        }
        let _ = std::fs::write(format!("{bundle_dir}/sysinfo.txt"), sysinfo);
        manifest.push("sysinfo.txt".into());
    }

    // ── MANIFEST ──────────────────────────────────────────────────────────
    {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mf = format!(
            "IONA Support Bundle\nGenerated: {ts}\nRPC: {rpc}\nData dir: {data_dir}\n\nFiles:\n{}\n",
            manifest.iter().map(|f| format!("  - {f}")).collect::<Vec<_>>().join("\n")
        );
        let _ = std::fs::write(format!("{bundle_dir}/MANIFEST.txt"), mf);
    }

    // ── Archive ───────────────────────────────────────────────────────────
    println!("\n  Creating archive: {output_path}...");
    let tar = std::process::Command::new("tar")
        .args([
            "czf",
            output_path,
            "-C",
            "/tmp",
            &format!("iona-support-{}", std::process::id()),
        ])
        .status();
    let _ = std::fs::remove_dir_all(&bundle_dir);

    match tar {
        Ok(s) if s.success() => {
            let size = std::fs::metadata(output_path).map(|m| m.len()).unwrap_or(0);
            println!("\n══════════════════════════════════════════");
            println!("  {} Support bundle created!", green("✓"));
            println!("  File : {output_path}");
            println!("  Size : {size} bytes");
            println!("  Send to support@example.invalid or attach to your GitHub issue.");
            println!("══════════════════════════════════════════\n");
        }
        _ => {
            eprintln!("  {} tar failed", red("FAIL"));
            process::exit(1);
        }
    }
}

// ── iona rbac check / rbac export ────────────────────────────────────────

fn cmd_rbac_check(rpc: &str, identity: &str, endpoint: &str) {
    println!("\n  RBAC check  identity={identity}  endpoint={endpoint}\n");
    match ureq::get(&format!(
        "{rpc}/admin/rbac/check?identity={identity}&endpoint={endpoint}"
    ))
    .timeout(std::time::Duration::from_secs(3))
    .call()
    {
        Ok(resp) => {
            let status = resp.status();
            if let Ok(v) = resp.into_json::<serde_json::Value>() {
                print_json(&v);
            }
            if status == 200 {
                println!("\n  {} Access ALLOWED", green("✓"));
            } else {
                println!("\n  {} Access DENIED (HTTP {status})", red("✗"));
                process::exit(1);
            }
        }
        Err(e) => die(&format!("RBAC check failed: {e}")),
    }
}

fn cmd_rbac_export(data_dir: &str) {
    for path in &[
        format!("{data_dir}/../rbac.toml"),
        "/etc/iona/rbac.toml".into(),
        "./rbac.toml".into(),
    ] {
        if !std::path::Path::new(path.as_str()).exists() {
            continue;
        }
        match std::fs::read_to_string(path) {
            Ok(content) => {
                println!("# Exported from: {path}\n{content}");
                return;
            }
            Err(e) => die(&format!("Cannot read {path}: {e}")),
        }
    }
    die("No rbac.toml found in <data_dir>/../rbac.toml, /etc/iona/rbac.toml, or ./rbac.toml");
}

// ── iona audit export / audit tail ───────────────────────────────────────

fn cmd_audit_export(path: &str, last_n: usize) {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(last_n);
            for line in &lines[start..] {
                println!("{line}");
            }
            eprintln!("\n  Exported {} entries from {path}", lines[start..].len());
        }
        Err(e) => die(&format!("Cannot read {path}: {e}")),
    }
}

fn cmd_audit_tail(path: &str, follow: bool) {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};

    // Print last 20 lines first
    {
        let f = std::fs::File::open(path).unwrap_or_else(|e| {
            eprintln!("Cannot open {path}: {e}");
            process::exit(1);
        });
        let lines: Vec<String> = BufReader::new(f).lines().filter_map(|l| l.ok()).collect();
        for line in &lines[lines.len().saturating_sub(20)..] {
            println!("{line}");
        }
    }

    if !follow {
        return;
    }

    println!("\n  {} Tailing {path} — Ctrl+C to stop\n", yellow("TAIL"));
    let mut f = std::fs::File::open(path).unwrap_or_else(|e| {
        eprintln!("Cannot open {path}: {e}");
        process::exit(1);
    });
    let _ = f.seek(SeekFrom::End(0));
    let mut reader = BufReader::new(f);
    let mut buf = String::new();
    loop {
        buf.clear();
        match reader.read_line(&mut buf) {
            Ok(0) => {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            Ok(_) => {
                print!("{}", buf.trim_end_matches('\n'));
                println!();
            }
            Err(e) => {
                eprintln!("Read error: {e}");
                break;
            }
        }
    }
}
