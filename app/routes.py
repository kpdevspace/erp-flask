import csv
import json
import os
from datetime import datetime
from decimal import Decimal, InvalidOperation
from functools import wraps
from io import BytesIO, StringIO

from flask import Blueprint, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from openpyxl import Workbook
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy import func, text

from . import db, limiter
from .auth import (
    api_auth_required,
    api_role_required,
    decode_token,
    hash_token,
    issue_access_token,
    issue_refresh_token,
    revoke_jti,
)
from .models import (
    AuditLog,
    Document,
    Invoice,
    Project,
    PurchaseOrder,
    RFQ,
    RefreshToken,
    User,
    Organization,
    Translation,
)

bp = Blueprint("erp", __name__)

MENU_ITEMS = [
    "Projects",
    "Request for Quotations",
    "Supplier Quotation",
    "Purchase Orders",
    "Purchase Invoices",
    "Quotations",
    "Orders",
    "Invoices",
    "Shipments",
    "Issues",
    "Addresses",
    "Timesheets",
    "Newsletter",
    "Material Request",
    "My Account",
]

WORKFLOW = {
    "draft": ["submitted"],
    "submitted": ["approved", "rejected"],
    "approved": [],
    "rejected": [],
}

SUPPORTED_LOCALES = ["th", "en", "zh"]
ALLOWED_KEY_PREFIXES = ["menu.", "common.", "errors.", "labels."]

DEFAULT_TRANSLATIONS = {
    "en": {
        "home": "Home",
        "reports": "Reports",
        "language_manage": "Language Management",
    },
    "th": {
        "home": "หน้าหลัก",
        "reports": "รายงาน",
        "language_manage": "จัดการภาษา",
    },
    "zh": {
        "home": "主页",
        "reports": "报表",
        "language_manage": "语言管理",
    },
}


def log_action(action: str, entity: str, entity_id=None, details: dict | None = None, actor_id=None):
    aid = actor_id
    if aid is None and getattr(current_user, "is_authenticated", False):
        aid = current_user.id
    db.session.add(
        AuditLog(
            actor_user_id=aid,
            action=action,
            entity=entity,
            entity_id=entity_id,
            details=json.dumps(details or {}),
        )
    )


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                flash("You do not have permission.", "danger")
                return redirect(url_for("erp.home"))
            return fn(*args, **kwargs)

        return login_required(wrapper)

    return decorator


def module_slug(title: str) -> str:
    return title.lower().replace(" ", "-")


def current_org_id():
    if getattr(current_user, "is_authenticated", False) and current_user.organization_id:
        return current_user.organization_id
    org = Organization.query.order_by(Organization.id.asc()).first()
    return org.id if org else None


def resolve_locale():
    qlang = (request.args.get("lang") or "").strip().lower()
    if qlang in SUPPORTED_LOCALES:
        session["lang"] = qlang
        return qlang
    if session.get("lang") in SUPPORTED_LOCALES:
        return session.get("lang")
    if getattr(current_user, "is_authenticated", False) and current_user.organization:
        if current_user.organization.default_locale in SUPPORTED_LOCALES:
            return current_user.organization.default_locale
    return "en"


def is_allowed_translation_key(key: str) -> bool:
    return any(key.startswith(prefix) for prefix in ALLOWED_KEY_PREFIXES)


def tr(key: str, default: str = ""):
    locale = resolve_locale()
    org_id = current_org_id()
    if org_id:
        row = Translation.query.filter_by(organization_id=org_id, locale=locale, key=key).first()
        if row and row.value:
            return row.value
    global_row = Translation.query.filter_by(organization_id=None, locale=locale, key=key).first()
    if global_row and global_row.value:
        return global_row.value
    return DEFAULT_TRANSLATIONS.get(locale, {}).get(key) or default or key


@bp.app_context_processor
def inject_i18n():
    return {
        "t": tr,
        "lang": resolve_locale(),
        "supported_locales": SUPPORTED_LOCALES,
    }


def parse_decimal(value, field_name: str):
    try:
        return Decimal(str(value or "0"))
    except (InvalidOperation, TypeError):
        raise ValueError(f"{field_name} must be a valid number")


def validate_required(data: dict, fields: list[str]):
    missing = [f for f in fields if not str(data.get(f, "")).strip()]
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")


def list_meta(page, per_page, total):
    return {"page": page, "per_page": per_page, "total": total, "total_pages": (total + per_page - 1) // per_page}


def get_page_args():
    page = max(1, request.args.get("page", default=1, type=int))
    per_page = min(100, max(1, request.args.get("per_page", default=20, type=int)))
    return page, per_page


def ensure_transition(current_status: str, next_status: str):
    allowed = WORKFLOW.get(current_status, [])
    if next_status not in allowed:
        raise ValueError(f"Invalid transition {current_status} -> {next_status}")


def serialize(model_name, row):
    base = {"id": row.id, "status": row.status, "created_at": row.created_at.isoformat()}
    if model_name == "rfq":
        return {**base, "rfq_no": row.rfq_no, "supplier_name": row.supplier_name, "total_amount": float(row.total_amount)}
    if model_name == "po":
        return {**base, "po_no": row.po_no, "vendor_name": row.vendor_name, "total_amount": float(row.total_amount)}
    return {**base, "invoice_no": row.invoice_no, "customer_name": row.customer_name, "total_amount": float(row.total_amount)}


def active_query(model):
    return model.query.filter(model.deleted_at.is_(None))


def report_data():
    rfqs = active_query(RFQ)
    pos = active_query(PurchaseOrder)
    invs = active_query(Invoice)
    return {
        "rfq_count": rfqs.count(),
        "po_count": pos.count(),
        "invoice_count": invs.count(),
        "po_total": float(pos.with_entities(func.coalesce(func.sum(PurchaseOrder.total_amount), 0)).scalar() or 0),
        "invoice_total": float(invs.with_entities(func.coalesce(func.sum(Invoice.total_amount), 0)).scalar() or 0),
        "unpaid_invoice_count": invs.filter(Invoice.status == "unpaid").count(),
    }


@bp.route("/init-admin")
def init_admin():
    org = Organization.query.filter_by(name="Default Organization").first()
    if not org:
        org = Organization(name="Default Organization", default_locale="en")
        db.session.add(org)
        db.session.flush()

    if User.query.filter_by(username="admin").first():
        db.session.commit()
        return "admin already exists", 200

    user = User(username="admin", role="admin", organization_id=org.id)
    user.set_password(os.getenv("ADMIN_DEFAULT_PASSWORD", "admin123"))
    db.session.add(user)
    db.session.commit()
    return "admin created", 201


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("erp.home"))
        flash("Invalid username/password", "danger")
    return render_template("login.html", menu_items=MENU_ITEMS)


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("erp.login"))


@bp.route("/set-language/<locale>")
@login_required
def set_language(locale):
    locale = (locale or "").lower()
    if locale in SUPPORTED_LOCALES:
        session["lang"] = locale
    return redirect(request.referrer or url_for("erp.home"))


@bp.route("/admin/languages", methods=["GET", "POST"])
@role_required("admin")
def admin_languages():
    org_id = request.args.get("org_id", type=int)
    scope = (request.args.get("scope") or "org").lower()
    if scope == "org" and not org_id:
        org_id = current_org_id()

    locale = (request.args.get("locale") or resolve_locale()).lower()
    if locale not in SUPPORTED_LOCALES:
        locale = "en"

    organizations = Organization.query.order_by(Organization.name.asc()).all()
    org = Organization.query.get(org_id) if org_id else None

    if request.method == "POST":
        form_type = request.form.get("form_type", "translation")
        if form_type == "org_locale" and org:
            new_locale = (request.form.get("default_locale") or "en").lower()
            if new_locale in SUPPORTED_LOCALES:
                org.default_locale = new_locale
                db.session.commit()
                flash("Organization default language updated", "success")
            return redirect(url_for("erp.admin_languages", scope="org", org_id=org.id, locale=new_locale))

        key = (request.form.get("key") or "").strip()
        value = (request.form.get("value") or "").strip()
        post_locale = (request.form.get("locale") or locale).lower()
        post_scope = (request.form.get("scope") or scope).lower()
        post_org_id = request.form.get("org_id", type=int) if post_scope == "org" else None

        if not is_allowed_translation_key(key):
            flash("Invalid key prefix. Allowed: menu., common., errors., labels.", "danger")
            return redirect(url_for("erp.admin_languages", scope=post_scope, org_id=post_org_id, locale=post_locale))

        if key and post_locale in SUPPORTED_LOCALES:
            row = Translation.query.filter_by(organization_id=post_org_id, locale=post_locale, key=key).first()
            if row:
                row.value = value
            else:
                db.session.add(Translation(organization_id=post_org_id, locale=post_locale, key=key, value=value))
            db.session.commit()
            flash("Translation saved", "success")
        return redirect(url_for("erp.admin_languages", scope=post_scope, org_id=post_org_id, locale=post_locale))

    rows = Translation.query.filter_by(organization_id=(org.id if scope == "org" and org else None), locale=locale).order_by(Translation.key.asc()).all()

    return render_template(
        "admin_languages.html",
        menu_items=MENU_ITEMS,
        organizations=organizations,
        selected_org=org,
        selected_locale=locale,
        rows=rows,
        scope=scope,
        allowed_key_prefixes=ALLOWED_KEY_PREFIXES,
    )


@bp.route("/admin/languages/export.csv")
@role_required("admin")
def admin_languages_export_csv():
    scope = (request.args.get("scope") or "org").lower()
    org_id = request.args.get("org_id", type=int) if scope == "org" else None
    locale = (request.args.get("locale") or resolve_locale()).lower()
    if locale not in SUPPORTED_LOCALES:
        locale = "en"

    rows = Translation.query.filter_by(organization_id=org_id, locale=locale).order_by(Translation.key.asc()).all()

    out = StringIO()
    writer = csv.writer(out)
    writer.writerow(["key", "value"])
    for r in rows:
        writer.writerow([r.key, r.value])
    payload = out.getvalue()
    out.close()

    prefix = f"org-{org_id}" if org_id else "global"
    return send_file(BytesIO(payload.encode("utf-8")), mimetype="text/csv", as_attachment=True, download_name=f"translations-{prefix}-{locale}.csv")


@bp.route("/admin/languages/import", methods=["POST"])
@role_required("admin")
def admin_languages_import():
    scope = (request.form.get("scope") or "org").lower()
    org_id = request.form.get("org_id", type=int) if scope == "org" else None
    locale = (request.form.get("locale") or "en").lower()
    csv_text = request.form.get("csv_text") or ""

    reader = csv.DictReader(StringIO(csv_text))
    upserts = 0
    for row in reader:
        key = (row.get("key") or "").strip()
        value = (row.get("value") or "").strip()
        if not key or not is_allowed_translation_key(key):
            continue
        existing = Translation.query.filter_by(organization_id=org_id, locale=locale, key=key).first()
        if existing:
            existing.value = value
        else:
            db.session.add(Translation(organization_id=org_id, locale=locale, key=key, value=value))
        upserts += 1

    db.session.commit()
    flash(f"Imported {upserts} translation rows", "success")
    return redirect(url_for("erp.admin_languages", scope=scope, org_id=org_id, locale=locale))


@bp.route("/api/token", methods=["POST"])
@limiter.limit("10 per minute")
def api_token():
    data = request.get_json(silent=True) or {}
    user = User.query.filter_by(username=str(data.get("username", "")).strip()).first()
    if not user or not user.check_password(str(data.get("password", ""))):
        return jsonify({"error": "invalid_credentials"}), 401

    access_token = issue_access_token(user)
    refresh_token = issue_refresh_token(user)
    log_action("token_issue", "auth", details={"user": user.username}, actor_id=user.id)
    db.session.commit()
    return jsonify({"access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer", "role": user.role})


@bp.route("/api/token/refresh", methods=["POST"])
@limiter.limit("20 per minute")
def api_token_refresh():
    data = request.get_json(silent=True) or {}
    raw = str(data.get("refresh_token", "")).strip()
    if not raw:
        return jsonify({"error": "refresh_token_required"}), 400

    try:
        payload = decode_token(raw)
        if payload.get("typ") != "refresh":
            return jsonify({"error": "invalid_token_type"}), 400
    except Exception:
        return jsonify({"error": "invalid_refresh_token"}), 401

    row = RefreshToken.query.filter_by(token_hash=hash_token(raw), is_revoked=False).first()
    if not row or row.expires_at < datetime.utcnow():
        return jsonify({"error": "refresh_token_expired_or_revoked"}), 401

    user = User.query.get(int(payload.get("sub")))
    access_token = issue_access_token(user)
    return jsonify({"access_token": access_token, "token_type": "Bearer"})


@bp.route("/api/token/revoke", methods=["POST"])
@limiter.limit("30 per minute")
@api_auth_required
def api_token_revoke():
    data = request.get_json(silent=True) or {}
    refresh_token = str(data.get("refresh_token", "")).strip()

    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            payload = decode_token(auth.split(" ", 1)[1].strip())
            revoke_jti(payload.get("jti"), payload.get("typ", "access"), payload.get("exp"))
        except Exception:
            pass

    if refresh_token:
        hashed = hash_token(refresh_token)
        row = RefreshToken.query.filter_by(token_hash=hashed).first()
        if row:
            row.is_revoked = True
    log_action("token_revoke", "auth", details={"by": request.api_user.username}, actor_id=request.api_user.id)
    db.session.commit()
    return jsonify({"message": "revoked"})


@bp.route("/health")
def health():
    return jsonify({"status": "ok"})


@bp.route("/ready")
def ready():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"status": "ready"})
    except Exception as exc:
        return jsonify({"status": "not_ready", "error": str(exc)}), 503


@bp.route("/")
@login_required
def home():
    return render_template("home.html", menu_items=MENU_ITEMS, kpi=report_data())


@bp.route("/reports")
@login_required
def reports_page():
    return render_template("reports.html", menu_items=MENU_ITEMS, kpi=report_data())


@bp.route("/reports/export.xlsx")
@login_required
def reports_export_xlsx():
    kpi = report_data()
    wb = Workbook()
    ws = wb.active
    ws.title = "ERP Report"
    ws.append(["Metric", "Value"])
    for key, value in kpi.items():
        ws.append([key, value])
    out = BytesIO()
    wb.save(out)
    out.seek(0)
    return send_file(out, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", as_attachment=True, download_name="erp-report.xlsx")


@bp.route("/reports/export.pdf")
@login_required
def reports_export_pdf():
    kpi = report_data()
    out = BytesIO()
    pdf = canvas.Canvas(out, pagesize=A4)
    y = 800
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "ERP Report")
    y -= 30
    pdf.setFont("Helvetica", 11)
    for key, value in kpi.items():
        pdf.drawString(50, y, f"{key}: {value}")
        y -= 20
    pdf.showPage()
    pdf.save()
    out.seek(0)
    return send_file(out, mimetype="application/pdf", as_attachment=True, download_name="erp-report.pdf")


@bp.route("/module/<slug>")
@login_required
def module_page(slug):
    title = next((i for i in MENU_ITEMS if module_slug(i) == slug), slug)
    recent_docs = Document.query.filter_by(module=slug).order_by(Document.created_at.desc()).limit(10).all()
    return render_template("modules/module_page.html", menu_items=MENU_ITEMS, title=title, slug=slug, recent_docs=recent_docs)


@bp.route("/projects")
@login_required
def projects():
    return render_template("modules/projects.html", menu_items=MENU_ITEMS, items=Project.query.order_by(Project.created_at.desc()).limit(30).all())


def _api_list(q, model_name):
    page, per_page = get_page_args()
    pagination = q.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({"data": [serialize(model_name, r) for r in pagination.items], "meta": list_meta(page, per_page, pagination.total)})


@bp.route("/api/rfqs", methods=["GET", "POST"])
@limiter.limit("120 per minute")
@api_auth_required
def api_rfqs():
    user = request.api_user
    if request.method == "POST":
        if user.role not in ["admin", "purchase"]:
            return jsonify({"error": "forbidden"}), 403
        data = request.get_json(silent=True) or {}
        validate_required(data, ["rfq_no", "supplier_name"])
        row = RFQ(rfq_no=data["rfq_no"].strip(), supplier_name=data["supplier_name"].strip(), total_amount=parse_decimal(data.get("total_amount"), "total_amount"), status=(data.get("status") or "draft").strip())
        db.session.add(row)
        log_action("create", "rfq", row.id, data, user.id)
        db.session.commit()
        return jsonify({"message": "created", "data": serialize("rfq", row)}), 201

    q = active_query(RFQ)
    s = (request.args.get("search") or "").strip()
    status = (request.args.get("status") or "").strip()
    if s:
        q = q.filter((RFQ.rfq_no.ilike(f"%{s}%")) | (RFQ.supplier_name.ilike(f"%{s}%")))
    if status:
        q = q.filter(RFQ.status == status)
    return _api_list(q.order_by(RFQ.created_at.desc()), "rfq")


@bp.route("/api/rfqs/<int:item_id>", methods=["GET", "PUT", "DELETE"])
@limiter.limit("120 per minute")
@api_auth_required
def api_rfqs_item(item_id):
    user = request.api_user
    row = active_query(RFQ).filter(RFQ.id == item_id).first_or_404()
    if request.method == "GET":
        return jsonify({"data": serialize("rfq", row)})
    if user.role not in ["admin", "purchase"]:
        return jsonify({"error": "forbidden"}), 403
    if request.method == "DELETE":
        row.deleted_at = datetime.utcnow()
        log_action("soft_delete", "rfq", row.id, actor_id=user.id)
        db.session.commit()
        return jsonify({"message": "soft_deleted"})
    data = request.get_json(silent=True) or {}
    if "supplier_name" in data:
        row.supplier_name = data["supplier_name"].strip()
    if "total_amount" in data:
        row.total_amount = parse_decimal(data.get("total_amount"), "total_amount")
    if "status" in data:
        row.status = (data.get("status") or row.status).strip()
    log_action("update", "rfq", row.id, data, user.id)
    db.session.commit()
    return jsonify({"message": "updated", "data": serialize("rfq", row)})


@bp.route("/api/rfqs/<int:item_id>/workflow", methods=["POST"])
@api_role_required("admin", "purchase")
def api_rfqs_workflow(item_id):
    row = active_query(RFQ).filter(RFQ.id == item_id).first_or_404()
    next_status = (request.get_json(silent=True) or {}).get("status", "").strip()
    ensure_transition(row.status, next_status)
    old = row.status
    row.status = next_status
    log_action("workflow_transition", "rfq", row.id, {"from": old, "to": next_status}, request.api_user.id)
    db.session.commit()
    return jsonify({"message": "transitioned", "data": serialize("rfq", row)})


@bp.route("/api/purchase-orders", methods=["GET", "POST"])
@limiter.limit("120 per minute")
@api_auth_required
def api_purchase_orders():
    user = request.api_user
    if request.method == "POST":
        if user.role not in ["admin", "purchase"]:
            return jsonify({"error": "forbidden"}), 403
        data = request.get_json(silent=True) or {}
        validate_required(data, ["po_no", "vendor_name"])
        row = PurchaseOrder(po_no=data["po_no"].strip(), vendor_name=data["vendor_name"].strip(), total_amount=parse_decimal(data.get("total_amount"), "total_amount"), status=(data.get("status") or "draft").strip())
        db.session.add(row)
        log_action("create", "purchase_order", row.id, data, user.id)
        db.session.commit()
        return jsonify({"message": "created", "data": serialize("po", row)}), 201

    q = active_query(PurchaseOrder)
    s = (request.args.get("search") or "").strip()
    status = (request.args.get("status") or "").strip()
    if s:
        q = q.filter((PurchaseOrder.po_no.ilike(f"%{s}%")) | (PurchaseOrder.vendor_name.ilike(f"%{s}%")))
    if status:
        q = q.filter(PurchaseOrder.status == status)
    return _api_list(q.order_by(PurchaseOrder.created_at.desc()), "po")


@bp.route("/api/purchase-orders/<int:item_id>", methods=["GET", "PUT", "DELETE"])
@limiter.limit("120 per minute")
@api_auth_required
def api_purchase_orders_item(item_id):
    user = request.api_user
    row = active_query(PurchaseOrder).filter(PurchaseOrder.id == item_id).first_or_404()
    if request.method == "GET":
        return jsonify({"data": serialize("po", row)})
    if user.role not in ["admin", "purchase"]:
        return jsonify({"error": "forbidden"}), 403
    if request.method == "DELETE":
        row.deleted_at = datetime.utcnow()
        log_action("soft_delete", "purchase_order", row.id, actor_id=user.id)
        db.session.commit()
        return jsonify({"message": "soft_deleted"})
    data = request.get_json(silent=True) or {}
    if "vendor_name" in data:
        row.vendor_name = data["vendor_name"].strip()
    if "total_amount" in data:
        row.total_amount = parse_decimal(data.get("total_amount"), "total_amount")
    if "status" in data:
        row.status = (data.get("status") or row.status).strip()
    log_action("update", "purchase_order", row.id, data, user.id)
    db.session.commit()
    return jsonify({"message": "updated", "data": serialize("po", row)})


@bp.route("/api/purchase-orders/<int:item_id>/workflow", methods=["POST"])
@api_role_required("admin", "purchase")
def api_purchase_orders_workflow(item_id):
    row = active_query(PurchaseOrder).filter(PurchaseOrder.id == item_id).first_or_404()
    next_status = (request.get_json(silent=True) or {}).get("status", "").strip()
    ensure_transition(row.status, next_status)
    old = row.status
    row.status = next_status
    log_action("workflow_transition", "purchase_order", row.id, {"from": old, "to": next_status}, request.api_user.id)
    db.session.commit()
    return jsonify({"message": "transitioned", "data": serialize("po", row)})


@bp.route("/api/invoices", methods=["GET", "POST"])
@limiter.limit("120 per minute")
@api_auth_required
def api_invoices():
    user = request.api_user
    if request.method == "POST":
        if user.role not in ["admin", "accounting", "sales"]:
            return jsonify({"error": "forbidden"}), 403
        data = request.get_json(silent=True) or {}
        validate_required(data, ["invoice_no", "customer_name"])
        row = Invoice(invoice_no=data["invoice_no"].strip(), customer_name=data["customer_name"].strip(), total_amount=parse_decimal(data.get("total_amount"), "total_amount"), status=(data.get("status") or "draft").strip())
        db.session.add(row)
        log_action("create", "invoice", row.id, data, user.id)
        db.session.commit()
        return jsonify({"message": "created", "data": serialize("invoice", row)}), 201

    q = active_query(Invoice)
    s = (request.args.get("search") or "").strip()
    status = (request.args.get("status") or "").strip()
    if s:
        q = q.filter((Invoice.invoice_no.ilike(f"%{s}%")) | (Invoice.customer_name.ilike(f"%{s}%")))
    if status:
        q = q.filter(Invoice.status == status)
    return _api_list(q.order_by(Invoice.created_at.desc()), "invoice")


@bp.route("/api/invoices/<int:item_id>", methods=["GET", "PUT", "DELETE"])
@limiter.limit("120 per minute")
@api_auth_required
def api_invoices_item(item_id):
    user = request.api_user
    row = active_query(Invoice).filter(Invoice.id == item_id).first_or_404()
    if request.method == "GET":
        return jsonify({"data": serialize("invoice", row)})
    if user.role not in ["admin", "accounting", "sales"]:
        return jsonify({"error": "forbidden"}), 403
    if request.method == "DELETE":
        row.deleted_at = datetime.utcnow()
        log_action("soft_delete", "invoice", row.id, actor_id=user.id)
        db.session.commit()
        return jsonify({"message": "soft_deleted"})
    data = request.get_json(silent=True) or {}
    if "customer_name" in data:
        row.customer_name = data["customer_name"].strip()
    if "total_amount" in data:
        row.total_amount = parse_decimal(data.get("total_amount"), "total_amount")
    if "status" in data:
        row.status = (data.get("status") or row.status).strip()
    log_action("update", "invoice", row.id, data, user.id)
    db.session.commit()
    return jsonify({"message": "updated", "data": serialize("invoice", row)})


@bp.route("/api/invoices/<int:item_id>/workflow", methods=["POST"])
@api_role_required("admin", "accounting")
def api_invoices_workflow(item_id):
    row = active_query(Invoice).filter(Invoice.id == item_id).first_or_404()
    next_status = (request.get_json(silent=True) or {}).get("status", "").strip()
    ensure_transition(row.status, next_status)
    old = row.status
    row.status = next_status
    log_action("workflow_transition", "invoice", row.id, {"from": old, "to": next_status}, request.api_user.id)
    db.session.commit()
    return jsonify({"message": "transitioned", "data": serialize("invoice", row)})


@bp.route("/api/audit-logs", methods=["GET"])
@api_role_required("admin")
def api_audit_logs():
    page, per_page = get_page_args()
    q = AuditLog.query.order_by(AuditLog.created_at.desc())
    pagination = q.paginate(page=page, per_page=per_page, error_out=False)
    rows = [
        {
            "id": r.id,
            "actor_user_id": r.actor_user_id,
            "action": r.action,
            "entity": r.entity,
            "entity_id": r.entity_id,
            "details": r.details,
            "created_at": r.created_at.isoformat(),
        }
        for r in pagination.items
    ]
    return jsonify({"data": rows, "meta": list_meta(page, per_page, pagination.total)})
