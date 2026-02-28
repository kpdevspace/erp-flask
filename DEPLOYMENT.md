# Deployment Guide (Production)

## 1) Environment variables
Set at minimum:

- `SECRET_KEY`
- `JWT_SECRET_KEY`
- `DATABASE_URL`
- `ADMIN_DEFAULT_PASSWORD`
- `CORS_ALLOWED_ORIGINS` (comma-separated, e.g. `https://erp.example.com`)
- `LOG_LEVEL` (`INFO`/`WARNING`)

## 2) Migrate database
```bash
flask --app run.py db migrate -m "production changes"
flask --app run.py db upgrade
```

## 3) Run with Docker
```bash
docker compose up -d --build
```

Port mapping:
- Web: `http://<host>:4000`
- API: `http://<host>:4002`
- PostgreSQL: `<host>:4003`

## 4) Health checks
- Liveness: `GET /health`
- Readiness: `GET /ready`

## 5) Backup / Restore
```bash
./scripts/backup.sh ./backups
./scripts/restore.sh ./backups/erpdb-YYYYMMDD-HHMMSS.dump
```

## 6) Security baseline
- Use HTTPS at reverse proxy level
- Restrict CORS to known frontend domains
- Rotate `JWT_SECRET_KEY` periodically
- Revoke tokens via `POST /api/token/revoke` during incident response
