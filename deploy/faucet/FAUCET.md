# IONA Testnet Faucet Configuration

**Chain:** iona-testnet-1 (chain_id=6126151)
**Endpoint:** `https://rpc.iona-testnet.example.com/faucet`

## Configuration

The faucet is enabled **only on the RPC node** via `enable_faucet = true` in `deploy/configs/rpc.toml`.

**No validators have faucet enabled.**

## Rate Limiting (nginx layer)

| Parameter | Value |
|-----------|-------|
| Requests per IP | 1 per minute |
| Burst | 3 requests |
| Max amount per request | 10,000 tokens |
| Max amount per address per day | 100,000 tokens |
| Cooldown per address | 60 seconds |

## Usage

```bash
curl -X POST https://rpc.iona-testnet.example.com/faucet \
  -H "Content-Type: application/json" \
  -d '{"address": "0xYOUR_ADDRESS", "amount": 1000}'
```

### Response (success)
```json
{
  "status": "ok",
  "tx_hash": "0x...",
  "amount": 1000,
  "address": "0xYOUR_ADDRESS"
}
```

### Response (rate limited)
```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many requests. Please retry after a moment.",
  "retry_after": 60
}
```

## Security

1. **Never expose faucet on validators** - only on the dedicated RPC node
2. **Always behind nginx proxy** - direct access to port 9000 is blocked by firewall
3. **Rate limiting at nginx level** - before the request reaches the node
4. **Treasury-funded** - faucet balance comes from a dedicated treasury account
5. **Monitoring** - all faucet requests are logged and monitored for abuse

## Disabling the Faucet

To disable the faucet:
1. Set `enable_faucet = false` in `deploy/configs/rpc.toml`
2. Restart the RPC node
3. The `/faucet` endpoint will return 404
