# Monitoring

- Start stack: `docker compose -f monitoring/docker-compose.yml up -d`
- Prometheus scrapes node metrics (adjust target).
- Grafana on :3000 (admin/admin by default in this scaffold).

TODO:
- Add dashboards JSON exports.
- Add alertmanager integration.
