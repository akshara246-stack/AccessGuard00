import os
from dotenv import load_dotenv

load_dotenv()
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from datetime import datetime
import random


# =========================================================
# FLASK CONFIGURATION
# =========================================================

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "accessguard"),
        port=int(os.getenv("DB_PORT", 3306))
    )


# =========================================================
# USER CLASS
# =========================================================

class User(UserMixin):

    def __init__(
        self,
        id,
        username,
        password_hash,
        email,
        department,
        role_id,
        status
    ):

        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.department = department
        self.role_id = role_id
        self.status = status


# =========================================================
# LOAD USER
# =========================================================

@login_manager.user_loader
def load_user(user_id):

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM users WHERE id = %s",
        (user_id,)
    )

    user = cursor.fetchone()

    cursor.close()
    db.close()

    if user:

        return User(
            user["id"],
            user["username"],
            user["password_hash"],
            user["email"],
            user["department"],
            user["role_id"],
            user["status"]
        )

    return None


# =========================================================
# GET ROLE NAME
# =========================================================

def get_role_name(role_id):

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute(
        "SELECT role_name FROM roles WHERE id = %s",
        (role_id,)
    )

    role = cursor.fetchone()

    cursor.close()
    db.close()

    if role:
        return role["role_name"]

    return "Unknown"


# =========================================================
# AUDIT LOG
# =========================================================

def log_action(action, details):

    try:

        db = get_db()
        cursor = db.cursor()

        username = "System"

        if current_user.is_authenticated:
            username = current_user.username

        cursor.execute("""
            INSERT INTO audit_logs
            (username, action, details, timestamp)
            VALUES (%s, %s, %s, %s)
        """, (
            username,
            action,
            details,
            datetime.now()
        ))

        db.commit()

        cursor.close()
        db.close()

    except Exception as e:

        print("Audit log error:", e)


# =========================================================
# SECURITY ALERT
# =========================================================

def create_alert(alert_type, description, severity="Medium"):

    try:

        db = get_db()
        cursor = db.cursor()

        cursor.execute("""
            INSERT INTO security_alerts
            (alert_type, description, severity, timestamp)
            VALUES (%s, %s, %s, %s)
        """, (
            alert_type,
            description,
            severity,
            datetime.now()
        ))

        db.commit()

        cursor.close()
        db.close()

    except Exception as e:

        print("Security alert error:", e)


# =========================================================
# DEFAULT ADMIN CREATION
# =========================================================

def create_default_admin():
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_username or not admin_password:
        print("Admin setup skipped.")
        return

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM users WHERE username = %s",
        (admin_username,)
    )

    admin = cursor.fetchone()

    if not admin:
        password_hash = generate_password_hash(admin_password)

        cursor.execute("""
            INSERT INTO users
            (username, password_hash, email, department, role_id, status)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            admin_username,
            password_hash,
            "admin@accessguard.com",
            "IT",
            1,
            "Active"
        ))

        db.commit()

        print("--------------------------------")
        print("Default admin account created")
        print("Username:", admin_username)
        print("--------------------------------")

    cursor.close()
    db.close()


# =========================================================
# LOGIN
# =========================================================

@app.route("/", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            "SELECT * FROM users WHERE username = %s",
            (username,)
        )

        user = cursor.fetchone()

        cursor.close()
        db.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            if user["status"] != "Active":

                flash("Your account is inactive.", "danger")

                return redirect(url_for("login"))

            login_user(
                User(
                    user["id"],
                    user["username"],
                    user["password_hash"],
                    user["email"],
                    user["department"],
                    user["role_id"],
                    user["status"]
                )
            )

            log_action(
                "Login",
                "User logged into AccessGuard"
            )

            return redirect(url_for("dashboard"))

        else:

            create_alert(
                "Failed Login",
                f"Failed login attempt for username: {username}",
                "High"
            )

            log_action(
                "Failed Login",
                f"Failed login attempt for username: {username}"
            )

            flash(
                "Invalid username or password.",
                "danger"
            )

    return render_template("login.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
@login_required
def logout():

    username = current_user.username

    log_action(
        "Logout",
        f"{username} logged out"
    )

    logout_user()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("login"))


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Total users
    cursor.execute(
        "SELECT COUNT(*) AS total FROM users"
    )

    total_users = cursor.fetchone()["total"]

    # Total access requests
    cursor.execute(
        "SELECT COUNT(*) AS total FROM access_requests"
    )

    total_requests = cursor.fetchone()["total"]

    # Pending requests
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM access_requests
        WHERE status = 'Pending'
    """)

    pending_requests = cursor.fetchone()["total"]

    # Security alerts
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM security_alerts
    """)

    total_alerts = cursor.fetchone()["total"]

    # Recent audit logs
    cursor.execute("""
        SELECT *
        FROM audit_logs
        ORDER BY timestamp DESC
        LIMIT 5
    """)

    recent_logs = cursor.fetchall()

    cursor.close()
    db.close()

    role_name = get_role_name(current_user.role_id)

    return render_template(
        "dashboard.html",
        total_users=total_users,
        total_requests=total_requests,
        pending_requests=pending_requests,
        total_alerts=total_alerts,
        recent_logs=recent_logs,
        role_name=role_name
    )


# =========================================================
# MODULE 1
# IDENTITY MANAGEMENT
# =========================================================

@app.route("/users")
@login_required
def users():

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            users.id,
            users.username,
            users.email,
            users.department,
            users.status,
            roles.role_name
        FROM users
        LEFT JOIN roles
        ON users.role_id = roles.id
        ORDER BY users.id DESC
    """)

    all_users = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "users.html",
        users=all_users
    )


# =========================================================
# ADD USER
# =========================================================

@app.route("/users/add", methods=["POST"])
@login_required
def add_user():

    username = request.form.get("username")
    email = request.form.get("email")
    department = request.form.get("department")
    role_id = request.form.get("role_id")
    password = request.form.get("password")

    if not username or not password:

        flash(
            "Username and password are required.",
            "danger"
        )

        return redirect(url_for("users"))

    password_hash = generate_password_hash(password)

    try:

        db = get_db()
        cursor = db.cursor()

        cursor.execute("""
            INSERT INTO users
            (username, password_hash, email, department, role_id, status)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            username,
            password_hash,
            email,
            department,
            role_id,
            "Active"
        ))

        db.commit()

        cursor.close()
        db.close()

        log_action(
            "User Created",
            f"Created user: {username}"
        )

        flash(
            "User created successfully.",
            "success"
        )

    except mysql.connector.Error as e:

        flash(
            f"Database error: {e}",
            "danger"
        )

    return redirect(url_for("users"))


# =========================================================
# MODULE 2
# AUTHENTICATION & MFA
# =========================================================

@app.route("/auth")
@login_required
def auth():

    return render_template("auth.html")


# =========================================================
# MFA SIMULATION
# =========================================================

@app.route("/auth/test", methods=["POST"])
@login_required
def auth_test():

    method = request.form.get("method")

    if method == "password":

        result = "Password authentication successful."

    elif method == "otp":

        otp = random.randint(100000, 999999)

        result = f"Demo OTP generated: {otp}"

    elif method == "biometric":

        result = "Biometric verification simulated successfully."

    elif method == "security_key":

        result = "Security key verification simulated successfully."

    else:

        result = "Unknown authentication method."

    log_action(
        "Authentication Test",
        f"Authentication method tested: {method}"
    )

    return render_template(
        "auth.html",
        result=result
    )


# =========================================================
# MODULE 3
# ROLE BASED ACCESS CONTROL
# =========================================================

@app.route("/rbac")
@login_required
def rbac():

    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Roles
    cursor.execute("""
        SELECT *
        FROM roles
        ORDER BY id
    """)

    roles = cursor.fetchall()

    # Permissions
    cursor.execute("""
        SELECT *
        FROM permissions
        ORDER BY id
    """)

    permissions = cursor.fetchall()

    # Role permissions
    cursor.execute("""
        SELECT
            roles.role_name,
            permissions.permission_name
        FROM role_permissions
        JOIN roles
        ON role_permissions.role_id = roles.id
        JOIN permissions
        ON role_permissions.permission_id = permissions.id
        ORDER BY roles.id
    """)

    role_permissions = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "rbac.html",
        roles=roles,
        permissions=permissions,
        role_permissions=role_permissions
    )


# =========================================================
# RBAC PERMISSION CHECK
# =========================================================

@app.route("/rbac/check", methods=["POST"])
@login_required
def rbac_check():

    permission = request.form.get("permission")

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT permissions.permission_name
        FROM role_permissions
        JOIN permissions
        ON role_permissions.permission_id = permissions.id
        WHERE role_permissions.role_id = %s
    """, (
        current_user.role_id,
    ))

    user_permissions = cursor.fetchall()

    cursor.close()
    db.close()

    allowed = False

    for item in user_permissions:

        if item["permission_name"] == permission:

            allowed = True
            break

    if allowed:

        result = f"ACCESS GRANTED: {permission}"

        log_action(
            "RBAC Access Granted",
            permission
        )

    else:

        result = f"ACCESS DENIED: {permission}"

        create_alert(
            "Unauthorized Access",
            f"{current_user.username} attempted to access {permission}",
            "High"
        )

        log_action(
            "RBAC Access Denied",
            permission
        )

    return render_template(
        "rbac.html",
        result=result
    )


# =========================================================
# MODULE 4
# ACCESS REQUESTS / LEAST PRIVILEGE
# =========================================================

@app.route("/access")
@login_required
def access():

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            access_requests.*,
            users.username
        FROM access_requests
        JOIN users
        ON access_requests.user_id = users.id
        ORDER BY access_requests.id DESC
    """)

    requests_list = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "access.html",
        requests=requests_list
    )


# =========================================================
# CREATE ACCESS REQUEST
# =========================================================

@app.route("/access/request", methods=["POST"])
@login_required
def access_request():

    resource = request.form.get("resource")
    reason = request.form.get("reason")

    if not resource:

        flash(
            "Please specify a resource.",
            "danger"
        )

        return redirect(url_for("access"))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        INSERT INTO access_requests
        (user_id, resource, reason, status, requested_at)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        current_user.id,
        resource,
        reason,
        "Pending",
        datetime.now()
    ))

    db.commit()

    cursor.close()
    db.close()

    log_action(
        "Access Request",
        f"Requested access to: {resource}"
    )

    flash(
        "Access request submitted.",
        "success"
    )

    return redirect(url_for("access"))


# =========================================================
# APPROVE / REJECT ACCESS REQUEST
# =========================================================

@app.route(
    "/access/<int:request_id>/<decision>",
    methods=["POST"]
)
@login_required
def access_decision(request_id, decision):

    if decision not in ["approve", "reject"]:

        flash(
            "Invalid decision.",
            "danger"
        )

        return redirect(url_for("access"))

    new_status = (
        "Approved"
        if decision == "approve"
        else "Rejected"
    )

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        UPDATE access_requests
        SET status = %s
        WHERE id = %s
    """, (
        new_status,
        request_id
    ))

    db.commit()

    cursor.close()
    db.close()

    log_action(
        "Access Request Decision",
        f"Request {request_id}: {new_status}"
    )

    flash(
        f"Request {new_status.lower()} successfully.",
        "success"
    )

    return redirect(url_for("access"))


# =========================================================
# MODULE 5
# SECURITY / ATTACK SIMULATION
# =========================================================

@app.route("/security")
@login_required
def security():

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT *
        FROM security_alerts
        ORDER BY timestamp DESC
        LIMIT 20
    """)

    alerts = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "security.html",
        alerts=alerts
    )


# =========================================================
# SECURITY SIMULATOR
# =========================================================

@app.route("/security/simulate", methods=["POST"])
@login_required
def security_simulate():

    attack_type = request.form.get("attack_type")

    if attack_type == "brute_force":

        description = (
            "Multiple failed login attempts detected. "
            "Possible brute-force attack."
        )

        severity = "High"

    elif attack_type == "privilege_escalation":

        description = (
            "User attempted to access a resource "
            "outside their assigned privileges."
        )

        severity = "Critical"

    elif attack_type == "unauthorized_access":

        description = (
            "Unauthorized access attempt detected."
        )

        severity = "High"

    elif attack_type == "suspicious_login":

        description = (
            "Suspicious login activity detected."
        )

        severity = "Medium"

    else:

        description = "Unknown security event simulated."

        severity = "Low"

    create_alert(
        attack_type,
        description,
        severity
    )

    log_action(
        "Security Simulation",
        f"Simulated event: {attack_type}"
    )

    flash(
        f"Security event simulated: {attack_type}",
        "warning"
    )

    return redirect(url_for("security"))


# =========================================================
# MODULE 6
# AUDIT & MONITORING
# =========================================================

@app.route("/audit")
@login_required
def audit():

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT *
        FROM audit_logs
        ORDER BY timestamp DESC
        LIMIT 100
    """)

    logs = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "audit.html",
        logs=logs
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    create_default_admin()

    app.run()
    