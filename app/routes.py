import os
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import func

from . import db
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


@bp.route("/")
@login_required
def home():
    kpi = {
        "rfq_count": db.session.query(func.count(RFQ.id)).scalar() or 0,
        "po_count": db.session.query(func.count(PurchaseOrder.id)).scalar() or 0,
        "invoice_count": db.session.query(func.count(Invoice.id)).scalar() or 0,
        "po_total": float(db.session.query(func.coalesce(func.sum(PurchaseOrder.total_amount), 0)).scalar() or 0),
        "invoice_total": float(db.session.query(func.coalesce(func.sum(Invoice.total_amount), 0)).scalar() or 0),
        "unpaid_invoice_count": db.session.query(func.count(Invoice.id)).filter(Invoice.status == "unpaid").scalar() or 0,
    }
    return render_template("home.html", menu_items=MENU_ITEMS, kpi=kpi)


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
    return render_template(
        "modules/module_page.html",
        menu_items=MENU_ITEMS,
        title=title,
        slug=slug,
        recent_docs=recent_docs,
    )


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
            total_amount = parse_decimal(request.form.get("total_amount"), "total_amount")
            item = RFQ(
                rfq_no=request.form["rfq_no"].strip(),
                supplier_name=request.form["supplier_name"].strip(),
                total_amount=total_amount,
                status=request.form.get("status", "draft").strip() or "draft",
            )
            db.session.add(item)
            db.session.commit()
            flash("RFQ created", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("erp.rfqs"))

    items = RFQ.query.order_by(RFQ.created_at.desc()).all()
    return render_template("modules/rfqs.html", menu_items=MENU_ITEMS, items=items)


@bp.route("/purchase-orders", methods=["GET", "POST"])
@role_required("admin", "purchase")
def purchase_orders():
    if request.method == "POST":
        try:
            validate_required(request.form, ["po_no", "vendor_name"])
            total_amount = parse_decimal(request.form.get("total_amount"), "total_amount")
            item = PurchaseOrder(
                po_no=request.form["po_no"].strip(),
                vendor_name=request.form["vendor_name"].strip(),
                total_amount=total_amount,
                status=request.form.get("status", "draft").strip() or "draft",
            )
            db.session.add(item)
            db.session.commit()
            flash("Purchase Order created", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("erp.purchase_orders"))

    items = PurchaseOrder.query.order_by(PurchaseOrder.created_at.desc()).all()
    return render_template("modules/purchase_orders.html", menu_items=MENU_ITEMS, items=items)


@bp.route("/invoices", methods=["GET", "POST"])
@role_required("admin", "accounting", "sales")
def invoices():
    if request.method == "POST":
        try:
            validate_required(request.form, ["invoice_no", "customer_name"])
            total_amount = parse_decimal(request.form.get("total_amount"), "total_amount")
            item = Invoice(
                invoice_no=request.form["invoice_no"].strip(),
                customer_name=request.form["customer_name"].strip(),
                total_amount=total_amount,
                status=request.form.get("status", "unpaid").strip() or "unpaid",
            )
            db.session.add(item)
            db.session.commit()
            flash("Invoice created", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
        return redirect(url_for("erp.invoices"))

    items = Invoice.query.order_by(Invoice.created_at.desc()).all()
    return render_template("modules/invoices.html", menu_items=MENU_ITEMS, items=items)


@bp.route("/api/rfqs", methods=["GET", "POST"])
@login_required
def api_rfqs():
    if request.method == "POST":
        if current_user.role not in ["admin", "purchase"]:
            return jsonify({"error": "forbidden"}), 403
        data = request.get_json(silent=True) or {}
        try:
            validate_required(data, ["rfq_no", "supplier_name"])
            item = RFQ(
                rfq_no=data["rfq_no"].strip(),
                supplier_name=data["supplier_name"].strip(),
                total_amount=parse_decimal(data.get("total_amount"), "total_amount"),
                status=(data.get("status") or "draft").strip(),
            )
            db.session.add(item)
            db.session.commit()
            return jsonify({"id": item.id, "message": "created"}), 201
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    page, per_page = get_page_args()
    q = RFQ.query
    search = (request.args.get("search") or "").strip()
    status = (request.args.get("status") or "").strip()
    if search:
        q = q.filter((RFQ.rfq_no.ilike(f"%{search}%")) | (RFQ.supplier_name.ilike(f"%{search}%")))
    if status:
        q = q.filter(RFQ.status == status)

    pagination = q.order_by(RFQ.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    rows = [
        {
            "id": r.id,
            "rfq_no": r.rfq_no,
            "supplier_name": r.supplier_name,
            "total_amount": float(r.total_amount),
            "status": r.status,
            "created_at": r.created_at.isoformat(),
        }
        for r in pagination.items
    ]
    return jsonify({"data": rows, "meta": list_meta(page, per_page, pagination.total)})


@bp.route("/api/purchase-orders", methods=["GET", "POST"])
@login_required
def api_purchase_orders():
    if request.method == "POST":
        if current_user.role not in ["admin", "purchase"]:
            return jsonify({"error": "forbidden"}), 403
        data = request.get_json(silent=True) or {}
        try:
            validate_required(data, ["po_no", "vendor_name"])
            item = PurchaseOrder(
                po_no=data["po_no"].strip(),
                vendor_name=data["vendor_name"].strip(),
                total_amount=parse_decimal(data.get("total_amount"), "total_amount"),
                status=(data.get("status") or "draft").strip(),
            )
            db.session.add(item)
            db.session.commit()
            return jsonify({"id": item.id, "message": "created"}), 201
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    page, per_page = get_page_args()
    q = PurchaseOrder.query
    search = (request.args.get("search") or "").strip()
    status = (request.args.get("status") or "").strip()
    if search:
        q = q.filter((PurchaseOrder.po_no.ilike(f"%{search}%")) | (PurchaseOrder.vendor_name.ilike(f"%{search}%")))
    if status:
        q = q.filter(PurchaseOrder.status == status)

    pagination = q.order_by(PurchaseOrder.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    rows = [
        {
            "id": r.id,
            "po_no": r.po_no,
            "vendor_name": r.vendor_name,
            "total_amount": float(r.total_amount),
            "status": r.status,
            "created_at": r.created_at.isoformat(),
        }
        for r in pagination.items
    ]
    return jsonify({"data": rows, "meta": list_meta(page, per_page, pagination.total)})


@bp.route("/api/invoices", methods=["GET", "POST"])
@login_required
def api_invoices():
    if request.method == "POST":
        if current_user.role not in ["admin", "accounting", "sales"]:
            return jsonify({"error": "forbidden"}), 403
        data = request.get_json(silent=True) or {}
        try:
            validate_required(data, ["invoice_no", "customer_name"])
            item = Invoice(
                invoice_no=data["invoice_no"].strip(),
                customer_name=data["customer_name"].strip(),
                total_amount=parse_decimal(data.get("total_amount"), "total_amount"),
                status=(data.get("status") or "unpaid").strip(),
            )
            db.session.add(item)
            db.session.commit()
            return jsonify({"id": item.id, "message": "created"}), 201
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    page, per_page = get_page_args()
    q = Invoice.query
    search = (request.args.get("search") or "").strip()
    status = (request.args.get("status") or "").strip()
    if search:
        q = q.filter((Invoice.invoice_no.ilike(f"%{search}%")) | (Invoice.customer_name.ilike(f"%{search}%")))
    if status:
        q = q.filter(Invoice.status == status)

    pagination = q.order_by(Invoice.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    rows = [
        {
            "id": r.id,
            "invoice_no": r.invoice_no,
            "customer_name": r.customer_name,
            "total_amount": float(r.total_amount),
            "status": r.status,
            "created_at": r.created_at.isoformat(),
        }
        for r in pagination.items
    ]
    return jsonify({"data": rows, "meta": list_meta(page, per_page, pagination.total)})
