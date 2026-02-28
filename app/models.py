from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, login_manager


class TimestampMixin:
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class User(db.Model, UserMixin, TimestampMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="staff")

    def set_password(self, raw_password: str):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Project(db.Model, TimestampMixin):
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), default="draft", nullable=False)
    customer_name = db.Column(db.String(200), nullable=True)


class Document(db.Model, TimestampMixin):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    module = db.Column(db.String(100), nullable=False, index=True)
    doc_no = db.Column(db.String(100), nullable=False, unique=True)
    title = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Numeric(14, 2), default=0)
    currency = db.Column(db.String(10), default="THB")
    status = db.Column(db.String(50), default="draft", nullable=False)


class RFQ(db.Model, TimestampMixin):
    __tablename__ = "rfqs"

    id = db.Column(db.Integer, primary_key=True)
    rfq_no = db.Column(db.String(100), unique=True, nullable=False)
    supplier_name = db.Column(db.String(200), nullable=False)
    total_amount = db.Column(db.Numeric(14, 2), default=0)
    status = db.Column(db.String(50), default="draft", nullable=False)


class PurchaseOrder(db.Model, TimestampMixin):
    __tablename__ = "purchase_orders"

    id = db.Column(db.Integer, primary_key=True)
    po_no = db.Column(db.String(100), unique=True, nullable=False)
    vendor_name = db.Column(db.String(200), nullable=False)
    total_amount = db.Column(db.Numeric(14, 2), default=0)
    status = db.Column(db.String(50), default="draft", nullable=False)


class Invoice(db.Model, TimestampMixin):
    __tablename__ = "invoices"

    id = db.Column(db.Integer, primary_key=True)
    invoice_no = db.Column(db.String(100), unique=True, nullable=False)
    customer_name = db.Column(db.String(200), nullable=False)
    total_amount = db.Column(db.Numeric(14, 2), default=0)
    status = db.Column(db.String(50), default="unpaid", nullable=False)
