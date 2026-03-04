# RPC auth (API key)

The ULTRA package includes a middleware template you can enable to protect
write endpoints.

- Header: `x-api-key` (configurable)
- Value: configured secret

Recommendation for production: use mTLS or reverse proxy auth (e.g., Nginx/Traefik)
and keep RPC bound to localhost by default.
