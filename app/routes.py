import os
from decimal import Decimal, InvalidOperation
from functools import wraps
from io import BytesIO

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import func
from openpyxl import Workbook
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from . import db
from .auth import issue_token, api_auth_required, api_role_required
from .models import Project, Document, User, RFQ, PurchaseOrder, Invoice


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
    return {
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": (total + per_page - 1) // per_page,
    }


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


def report_data():
    return {
        "rfq_count": db.session.query(func.count(RFQ.id)).scalar() or 0,
        "po_count": db.session.query(func.count(PurchaseOrder.id)).scalar() or 0,
        "invoice_count": db.session.query(func.count(Invoice.id)).scalar() or 0,
        "po_total": float(db.session.query(func.coalesce(func.sum(PurchaseOrder.total_amount), 0)).scalar() or 0),
        "invoice_total": float(db.session.query(func.coalesce(func.sum(Invoice.total_amount), 0)).scalar() or 0),
        "unpaid_invoice_count": db.session.query(func.count(Invoice.id)).filter(Invoice.status == "unpaid").scalar() or 0,
    }


@bp.route("/init-admin")
def init_admin():
    if User.query.filter_by(username="admin").first():
        return "admin already exists", 200

    user = User(username="admin", role="admin")
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


@bp.route("/api/token", methods=["POST"])
def api_token():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "invalid_credentials"}), 401
    token = issue_token(user)
    return jsonify({"access_token": token, "token_type": "Bearer", "role": user.role})


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
    recent_docs = (
        Document.query.filter_by(module=slug)
        .order_by(Document.created_at.desc())
        .limit(10)
        .all()
    )
    return render_template("modules/module_page.html", menu_items=MENU_ITEMS, title=title, slug=slug, recent_docs=recent_docs)


@bp.route("/projects")
@login_required
def projects():
    items = Project.query.order_by(Project.created_at.desc()).limit(30).all()
    return render_template("modules/projects.html", menu_items=MENU_ITEMS, items=items)


@bp.route("/rfqs", methods=["GET", "POST"])
@role_required("admin", "purchase")
def rfqs():
    if request.method == "POST":
        try:
            validate_required(request.form, ["rfq_no", "supplier_name"])
            item = RFQ(rfq_no=request.form["rfq_no"].strip(), supplier_name=request.form["supplier_name"].strip(), total_amount=parse_decimal(request.form.get("total_amount"), "total_amount"), status=request.form.get("status", "draft").strip() or "draft")
            db.session.add(item)
            db.session.commit()
            flash("RFQ created", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("erp.rfqs"))
    return render_template("modules/rfqs.html", menu_items=MENU_ITEMS, items=RFQ.query.order_by(RFQ.created_at.desc()).all())


@bp.route("/purchase-orders", methods=["GET", "POST"])
@role_required("admin", "purchase")
def purchase_orders():
    if request.method == "POST":
        try:
            validate_required(request.form, ["po_no", "vendor_name"])
            item = PurchaseOrder(po_no=request.form["po_no"].strip(), vendor_name=request.form["vendor_name"].strip(), total_amount=parse_decimal(request.form.get("total_amount"), "total_amount"), status=request.form.get("status", "draft").strip() or "draft")
            db.session.add(item)
            db.session.commit()
            flash("Purchase Order created", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("erp.purchase_orders"))
    return render_template("modules/purchase_orders.html", menu_items=MENU_ITEMS, items=PurchaseOrder.query.order_by(PurchaseOrder.created_at.desc()).all())


@bp.route("/invoices", methods=["GET", "POST"])
@role_required("admin", "accounting", "sales")
def invoices():
    if request.method == "POST":
        try:
            validate_required(request.form, ["invoice_no", "customer_name"])
            item = Invoice(invoice_no=request.form["invoice_no"].strip(), customer_name=request.form["customer_name"].strip(), total_amount=parse_decimal(request.form.get("total_amount"), "total_amount"), status=request.form.get("status", "unpaid").strip() or "unpaid")
            db.session.add(item)
            db.session.commit()
            flash("Invoice created", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("erp.invoices"))
    return render_template("modules/invoices.html", menu_items=MENU_ITEMS, items=Invoice.query.order_by(Invoice.created_at.desc()).all())


def _api_list(q, model_name):
    page, per_page = get_page_args()
    pagination = q.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({"data": [serialize(model_name, r) for r in pagination.items], "meta": list_meta(page, per_page, pagination.total)})


@bp.route("/api/rfqs", methods=["GET", "POST"])
@api_auth_required
def api_rfqs():
    user = request.api_user
    if request.method == "POST":
        if user.role not in ["admin", "purchase"]:
            return jsonify({"error": "forbidden"}), 403
        data = request.get_json(silent=True) or {}
        try:
            validate_required(data, ["rfq_no", "supplier_name"])
            row = RFQ(rfq_no=data["rfq_no"].strip(), supplier_name=data["supplier_name"].strip(), total_amount=parse_decimal(data.get("total_amount"), "total_amount"), status=(data.get("status") or "draft").strip())
            db.session.add(row)
            db.session.commit()
            return jsonify({"message": "created", "data": serialize("rfq", row)}), 201
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    q = RFQ.query
    s = (request.args.get("search") or "").strip()
    status = (request.args.get("status") or "").strip()
    if s:
        q = q.filter((RFQ.rfq_no.ilike(f"%{s}%")) | (RFQ.supplier_name.ilike(f"%{s}%")))
    if status:
        q = q.filter(RFQ.status == status)
    return _api_list(q.order_by(RFQ.created_at.desc()), "rfq")


@bp.route("/api/rfqs/<int:item_id>", methods=["GET", "PUT", "DELETE"])
@api_auth_required
def api_rfqs_item(item_id):
    user = request.api_user
    row = RFQ.query.get_or_404(item_id)
    if request.method == "GET":
        return jsonify({"data": serialize("rfq", row)})
    if user.role not in ["admin", "purchase"]:
        return jsonify({"error": "forbidden"}), 403
    if request.method == "DELETE":
        db.session.delete(row)
        db.session.commit()
        return jsonify({"message": "deleted"})
    data = request.get_json(silent=True) or {}
    if "supplier_name" in data:
        row.supplier_name = data["supplier_name"].strip()
    if "total_amount" in data:
        row.total_amount = parse_decimal(data.get("total_amount"), "total_amount")
    if "status" in data:
        row.status = (data.get("status") or row.status).strip()
    db.session.commit()
    return jsonify({"message": "updated", "data": serialize("rfq", row)})


@bp.route("/api/rfqs/<int:item_id>/workflow", methods=["POST"])
@api_role_required("admin", "purchase")
def api_rfqs_workflow(item_id):
    row = RFQ.query.get_or_404(item_id)
    next_status = (request.get_json(silent=True) or {}).get("status", "").strip()
    try:
        ensure_transition(row.status, next_status)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    row.status = next_status
    db.session.commit()
    return jsonify({"message": "transitioned", "data": serialize("rfq", row)})


@bp.route("/api/purchase-orders", methods=["GET", "POST"])
@api_auth_required
def api_purchase_orders():
    user = request.api_user
    if request.method == "POST":
        if user.role not in ["admin", "purchase"]:
            return jsonify({"error": "forbidden"}), 403
        data = request.get_json(silent=True) or {}
        try:
            validate_required(data, ["po_no", "vendor_name"])
            row = PurchaseOrder(po_no=data["po_no"].strip(), vendor_name=data["vendor_name"].strip(), total_amount=parse_decimal(data.get("total_amount"), "total_amount"), status=(data.get("status") or "draft").strip())
            db.session.add(row)
            db.session.commit()
            return jsonify({"message": "created", "data": serialize("po", row)}), 201
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    q = PurchaseOrder.query
    s = (request.args.get("search") or "").strip()
    status = (request.args.get("status") or "").strip()
    if s:
        q = q.filter((PurchaseOrder.po_no.ilike(f"%{s}%")) | (PurchaseOrder.vendor_name.ilike(f"%{s}%")))
    if status:
        q = q.filter(PurchaseOrder.status == status)
    return _api_list(q.order_by(PurchaseOrder.created_at.desc()), "po")


@bp.route("/api/purchase-orders/<int:item_id>", methods=["GET", "PUT", "DELETE"])
@api_auth_required
def api_purchase_orders_item(item_id):
    user = request.api_user
    row = PurchaseOrder.query.get_or_404(item_id)
    if request.method == "GET":
        return jsonify({"data": serialize("po", row)})
    if user.role not in ["admin", "purchase"]:
        return jsonify({"error": "forbidden"}), 403
    if request.method == "DELETE":
        db.session.delete(row)
        db.session.commit()
        return jsonify({"message": "deleted"})
    data = request.get_json(silent=True) or {}
    if "vendor_name" in data:
        row.vendor_name = data["vendor_name"].strip()
    if "total_amount" in data:
        row.total_amount = parse_decimal(data.get("total_amount"), "total_amount")
    if "status" in data:
        row.status = (data.get("status") or row.status).strip()
    db.session.commit()
    return jsonify({"message": "updated", "data": serialize("po", row)})


@bp.route("/api/purchase-orders/<int:item_id>/workflow", methods=["POST"])
@api_role_required("admin", "purchase")
def api_purchase_orders_workflow(item_id):
    row = PurchaseOrder.query.get_or_404(item_id)
    next_status = (request.get_json(silent=True) or {}).get("status", "").strip()
    try:
        ensure_transition(row.status, next_status)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    row.status = next_status
    db.session.commit()
    return jsonify({"message": "transitioned", "data": serialize("po", row)})


@bp.route("/api/invoices", methods=["GET", "POST"])
@api_auth_required
def api_invoices():
    user = request.api_user
    if request.method == "POST":
        if user.role not in ["admin", "accounting", "sales"]:
            return jsonify({"error": "forbidden"}), 403
        data = request.get_json(silent=True) or {}
        try:
            validate_required(data, ["invoice_no", "customer_name"])
            row = Invoice(invoice_no=data["invoice_no"].strip(), customer_name=data["customer_name"].strip(), total_amount=parse_decimal(data.get("total_amount"), "total_amount"), status=(data.get("status") or "draft").strip())
            db.session.add(row)
            db.session.commit()
            return jsonify({"message": "created", "data": serialize("invoice", row)}), 201
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    q = Invoice.query
    s = (request.args.get("search") or "").strip()
    status = (request.args.get("status") or "").strip()
    if s:
        q = q.filter((Invoice.invoice_no.ilike(f"%{s}%")) | (Invoice.customer_name.ilike(f"%{s}%")))
    if status:
        q = q.filter(Invoice.status == status)
    return _api_list(q.order_by(Invoice.created_at.desc()), "invoice")


@bp.route("/api/invoices/<int:item_id>", methods=["GET", "PUT", "DELETE"])
@api_auth_required
def api_invoices_item(item_id):
    user = request.api_user
    row = Invoice.query.get_or_404(item_id)
    if request.method == "GET":
        return jsonify({"data": serialize("invoice", row)})
    if user.role not in ["admin", "accounting", "sales"]:
        return jsonify({"error": "forbidden"}), 403
    if request.method == "DELETE":
        db.session.delete(row)
        db.session.commit()
        return jsonify({"message": "deleted"})
    data = request.get_json(silent=True) or {}
    if "customer_name" in data:
        row.customer_name = data["customer_name"].strip()
    if "total_amount" in data:
        row.total_amount = parse_decimal(data.get("total_amount"), "total_amount")
    if "status" in data:
        row.status = (data.get("status") or row.status).strip()
    db.session.commit()
    return jsonify({"message": "updated", "data": serialize("invoice", row)})


@bp.route("/api/invoices/<int:item_id>/workflow", methods=["POST"])
@api_role_required("admin", "accounting")
def api_invoices_workflow(item_id):
    row = Invoice.query.get_or_404(item_id)
    next_status = (request.get_json(silent=True) or {}).get("status", "").strip()
    try:
        ensure_transition(row.status, next_status)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    row.status = next_status
    db.session.commit()
    return jsonify({"message": "transitioned", "data": serialize("invoice", row)})
