# ERP Flask Skeleton

> License: MIT — Copyright (c) 2026 Vikornsak (vikornsak@gmail.com)
> 
> If you use or redistribute this project, keep the copyright and license notice.

Starter ERP web system based on:
- Python Flask
- Bulma CSS
- PostgreSQL (latest supported via `psycop`)

## Modules (from provided menu)
- Projects
- Request for Quotations
- Supplier Quotation
- Purchase Orders
- Purchase Invoices
- Quotations
- Orders
- Invoices
- Shipments
- Issues
- Addresses
- Timesheets
- Newsletter
- Material Request
- My Account

## Quick Start

```bash
cd erp-flask
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Create PostgreSQL DB:

```sql
CREATE DATABASE erpdb;
```

Run migrations:

```bash
export FLASK_APP=run.py
flask db init
flask db migrate -m "init erp schema"
flask db upgrade
```

Run app:

```bash
python run.py
```

Open: http://127.0.0.1:5000

## Docker (Flask + PostgreSQL)

```bash
docker compose up -d --build
```

Then migrate DB inside container:

```bash
docker compose exec web flask --app run.py db init
docker compose exec web flask --app run.py db migrate -m "init schema"
docker compose exec web flask --app run.py db upgrade
```

Open: http://127.0.0.1:5000

## API examples

```bash
# 1) get token
curl -X POST http://127.0.0.1:5000/api/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# 2) call API with Bearer token
curl "http://127.0.0.1:5000/api/rfqs?page=1&per_page=20&search=ABC&status=draft" \
  -H "Authorization: Bearer <ACCESS_TOKEN>"

# 3) workflow transition
curl -X POST http://127.0.0.1:5000/api/rfqs/1/workflow \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"status":"submitted"}'
```

## Architecture

- `app/models.py` contains starter tables:
  - `projects`
  - `documents` (generic per module)
- `app/routes.py` includes menu-driven module routes.
- `templates/base.html` provides Bulma sidebar UI.

## Included in current scaffold
1. Authentication (Flask-Login)
2. Role-based access (admin/purchase/accounting/sales)
3. CRUD starter pages:
   - Request for Quotations (`/rfqs`)
   - Purchase Orders (`/purchase-orders`)
   - Invoices (`/invoices`)
4. Dashboard KPI cards (counts + totals)
5. REST APIs with validation/filter/search/pagination:
   - `GET/POST /api/rfqs`
   - `GET/POST /api/purchase-orders`
   - `GET/POST /api/invoices`
   - `GET/PUT/DELETE /api/rfqs/<id>`
   - `GET/PUT/DELETE /api/purchase-orders/<id>`
   - `GET/PUT/DELETE /api/invoices/<id>`
   - Query params: `page`, `per_page`, `search`, `status`
6. JWT token auth for client apps (`POST /api/token`)
   - refresh token: `POST /api/token/refresh`
   - revoke token: `POST /api/token/revoke`
7. Approval workflow endpoint:
   - `POST /api/rfqs/<id>/workflow`
   - `POST /api/purchase-orders/<id>/workflow`
   - `POST /api/invoices/<id>/workflow`
   - transition: `draft -> submitted -> approved/rejected`
8. Report page + export:
   - `/reports`
   - `/reports/export.xlsx`
   - `/reports/export.pdf`
9. Soft delete for API DELETE actions (RFQ/PO/Invoice)
10. Audit logs endpoint (admin only): `GET /api/audit-logs`
11. CI workflow (GitHub Actions): `.github/workflows/ci.yml`
12. Health/Readiness endpoints: `/health`, `/ready`
13. Rate limiting + CORS policy for `/api/*`
14. Backup/restore scripts: `scripts/backup.sh`, `scripts/restore.sh`
15. Production deployment guide: `DEPLOYMENT.md`

## Initial admin
1. Open `/init-admin` once to create default admin.
2. Login at `/login` with:
   - username: `admin`
   - password: value in `ADMIN_DEFAULT_PASSWORD` from `.env`

## Next suggested steps
1. Add form validation (WTForms/Pydantic)
2. Add REST API endpoints + pagination/filtering
3. Add approval workflow + status transitions
4. Add audit log and report exports
