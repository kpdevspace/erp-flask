# ERP Flask Skeleton

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
# login first (session cookie), then call
curl "http://127.0.0.1:5000/api/rfqs?page=1&per_page=20&search=ABC&status=draft"
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
   - Query params: `page`, `per_page`, `search`, `status`

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
