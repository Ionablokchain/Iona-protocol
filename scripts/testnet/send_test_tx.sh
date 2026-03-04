#!/usr/bin/env bash
# ============================================================================
# IONA Testnet — Send Test Transactions
# ============================================================================
# Sends test transactions to the testnet for validation.
#
# Usage:
#   ./scripts/testnet/send_test_tx.sh [OPTIONS]
#
# Options:
#   --rpc URL          RPC endpoint (default: http://127.0.0.1:19001)
#   --count N          Number of transactions to send (default: 10)
#   --delay MS         Delay between transactions in ms (default: 100)
#   --payload CMD      Transaction payload (default: "set testkey testvalue")
# ============================================================================

set -euo pipefail

RPC_URL="http://127.0.0.1:19001"
TX_COUNT=10
DELAY_MS=100
PAYLOAD="set testkey testvalue"

while [[ $# -gt 0 ]]; do
    case $1 in
        --rpc)     RPC_URL="$2"; shift 2 ;;
        --count)   TX_COUNT="$2"; shift 2 ;;
        --delay)   DELAY_MS="$2"; shift 2 ;;
        --payload) PAYLOAD="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "============================================"
echo " IONA Testnet — Send Test Transactions"
echo "============================================"
echo " RPC:     $RPC_URL"
echo " Count:   $TX_COUNT"
echo " Delay:   ${DELAY_MS}ms"
echo " Payload: $PAYLOAD"
echo "============================================"
echo ""

# Check node is healthy
echo "Checking node health..."
if ! curl -s -m 2 "$RPC_URL/health" > /dev/null 2>&1; then
    echo "Error: Node at $RPC_URL is not responding"
    exit 1
fi
echo "  Node is healthy"
echo ""

# Send transactions via JSON-RPC
SUCCESSES=0
FAILURES=0

for i in $(seq 1 "$TX_COUNT"); do
    # Use unique payload per tx
    TX_PAYLOAD="set testkey_${i} testvalue_${i}_$(date +%s%N)"

    RESULT=$(curl -s -m 5 -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d "{
            \"jsonrpc\": \"2.0\",
            \"method\": \"eth_sendRawTransaction\",
            \"params\": [\"$TX_PAYLOAD\"],
            \"id\": $i
        }" 2>/dev/null || echo "CONNECTION_ERROR")

    if [[ "$RESULT" == "CONNECTION_ERROR" ]]; then
        echo "  [$i/$TX_COUNT] FAIL: Connection error"
        FAILURES=$((FAILURES + 1))
    elif echo "$RESULT" | grep -q '"error"'; then
        ERROR=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error', {}).get('message', 'unknown'))" 2>/dev/null || echo "parse error")
        echo "  [$i/$TX_COUNT] ERROR: $ERROR"
        FAILURES=$((FAILURES + 1))
    else
        echo "  [$i/$TX_COUNT] OK"
        SUCCESSES=$((SUCCESSES + 1))
    fi

    # Delay between transactions
    if [[ $i -lt $TX_COUNT ]] && [[ $DELAY_MS -gt 0 ]]; then
        sleep "$(echo "scale=3; $DELAY_MS / 1000" | bc)"
    fi
done

echo ""
echo "============================================"
echo " Results: $SUCCESSES/$TX_COUNT succeeded, $FAILURES failed"
echo "============================================"

# Check final block height
echo ""
echo "Current block height:"
curl -s -m 2 -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    result = d.get('result', 'N/A')
    if isinstance(result, str) and result.startswith('0x'):
        print(f'  Height: {int(result, 16)} ({result})')
    else:
        print(f'  Height: {result}')
except:
    print('  Unable to parse response')
" 2>/dev/null || echo "  Unable to get block height"
