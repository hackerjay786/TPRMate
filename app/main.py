import datetime as dt
import os

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, send_file, url_for
from flask_login import login_required

from .forms import VendorForm
from .models import AuditEvent, Finding, ScanRun, Vendor, db
from .services.parse import parse_active_line, parse_passive_line
from .services.process_manager import launch_active, launch_passive
from .services.report import build_report
from .services.simulate import run_simulation
from .utils import slugify
from .models import db, Vendor, ScanRun, Finding, AuditEvent, User
from .forms import VendorForm, UserForm
from flask_login import current_user

main_bp = Blueprint("main", __name__)

@main_bp.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    if current_user.role != "Admin":
        flash("Only admins can manage users.", "danger")
        return redirect(url_for("main.dashboard"))

    form = UserForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()

        if User.query.filter_by(email=email).first():
            flash("User already exists.", "warning")
        else:
            user = User(
                email=email,
                role=form.role.data.strip() or "Viewer"
            )
            user.set_password(form.password.data)

            db.session.add(user)
            db.session.add(AuditEvent(
                event_type="user_create",
                message=f"User created: {email}",
                user_id=current_user.id
            ))
            db.session.commit()

            flash("User added successfully.", "success")
            return redirect(url_for("main.users"))

    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("users.html", form=form, users=users)


@main_bp.route("/")
def index():
    from flask_login import current_user

    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    return render_template("index.html")


def _empty_severity_counts():
    return {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }


def _count_findings(findings):
    counts = _empty_severity_counts()

    for f in findings or []:
        severity = (getattr(f, "severity", None) or "low").lower()

        if severity in counts:
            counts[severity] += 1

    return counts


@main_bp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = VendorForm()

    if form.validate_on_submit():
        if Vendor.query.filter_by(name=form.name.data.strip()).first():
            flash('Vendor exists', 'warning')
        else:
            v = Vendor(
                name=form.name.data.strip(),
                domain=(form.domain.data.strip() if form.domain.data else None),
                consent=form.consent.data
            )
            db.session.add(v)
            db.session.commit()
            flash('Vendor added', 'success')
            return redirect(url_for('main.dashboard'))

    vendors = Vendor.query.order_by(Vendor.created_at.desc()).all()
    latest = {v.id: ScanRun.query.filter_by(vendor_id=v.id).order_by(ScanRun.started_at.desc()).first() for v in vendors}
    vendor_counts = {}
    for v in vendors:
        runs = ScanRun.query.filter_by(vendor_id=v.id).all()
        counts = {'low':0,'medium':0,'high':0,'critical':0}
        for r in runs:
            for f in r.findings:
                s = (f.severity or 'low').lower()
                if s in counts:
                    counts[s] += 1
        vendor_counts[v.id] = counts
    runs = ScanRun.query.all()

    total_runs = len(runs)
    completed = len([r for r in runs if r.status=='completed'])
    p50s = [r.p50 for r in runs if r.p50 is not None]
    avg_p50 = round(sum(p50s)/len(p50s), 2) if p50s else 0

    sev_counts = {'low':0,'medium':0,'high':0,'critical':0}
    for r in runs:
        for f in r.findings:
            s=(f.severity or 'low').lower()
            if s in sev_counts: sev_counts[s]+=1

    return render_template(
        'dashboard.html',
        vendors=vendors,
        latest=latest,
        total_runs=total_runs,
        completed=completed,
        avg_p50=avg_p50,
        sev_counts=sev_counts,
        vendor_counts=vendor_counts,  # 👈 ADD THIS
        form=form
    )  


@main_bp.route("/vendors", methods=["GET", "POST"])
@login_required
def vendors():
    form = VendorForm()

    if form.validate_on_submit():
        name = form.name.data.strip()
        domain = form.domain.data.strip() if form.domain.data else None

        if Vendor.query.filter_by(name=name).first():
            flash("Vendor exists", "warning")
        else:
            vendor = Vendor(
                name=name,
                domain=domain,
                consent=form.consent.data,
            )

            db.session.add(vendor)
            db.session.commit()

            flash("Vendor added", "success")
            return redirect(url_for("main.vendors"))

    vendors = Vendor.query.order_by(Vendor.created_at.desc()).all()

    return render_template("vendors.html", form=form, vendors=vendors)


@main_bp.route("/vendor/<int:vendor_id>")
@login_required
def vendor_detail(vendor_id):
    vendor = db.session.get(Vendor, vendor_id)

    if not vendor:
        flash("Vendor not found", "danger")
        return redirect(url_for("main.vendors"))

    vendor_runs = (
        ScanRun.query
        .filter_by(vendor_id=vendor.id)
        .order_by(ScanRun.started_at.desc())
        .all()
    )

    run = vendor_runs[0] if vendor_runs else None

    vendor_findings = (
        Finding.query
        .join(ScanRun, Finding.run_id == ScanRun.id)
        .filter(ScanRun.vendor_id == vendor.id)
        .order_by(Finding.id.desc())
        .all()
    )

    counts = _count_findings(vendor_findings)

    return render_template(
        "vendor_detail.html",
        vendor=vendor,
        run=run,
        vendor_runs=vendor_runs,
        findings=vendor_findings,
        counts=counts,
    )


@main_bp.route("/run/start/<int:vendor_id>", methods=["POST"])
@login_required
def start_run(vendor_id):
    vendor = db.session.get(Vendor, vendor_id)

    if not vendor:
        flash("Vendor not found", "danger")
        return redirect(url_for("main.vendors"))

    stamp = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    vendor_slug = slugify(vendor.name)

    run_dir = os.path.abspath(
        os.path.join(os.getcwd(), "data", "runs", f"{stamp}_{vendor_slug}")
    )
    os.makedirs(run_dir, exist_ok=True)

    run = ScanRun(
        vendor_id=vendor.id,
        run_path=run_dir,
        status="running",
        passive_status="running",
        active_status="running" if vendor.consent else "skipped",
    )

    run.passive_path = os.path.join(run_dir, "passive.log")
    run.active_path = os.path.join(run_dir, "active.log")

    db.session.add(run)
    db.session.commit()

    target_domain = vendor.domain or f"{vendor_slug}.example.com"

    run.passive_pid = launch_passive(
        target_domain,
        run.passive_path,
        current_app.config["REAL_SCANS"],
        current_app.config["FAST_DEMO"],
    )

    if vendor.consent:
        run.active_pid = launch_active(
            target_domain,
            run.active_path,
            current_app.config["REAL_SCANS"],
            vendor.consent,
            current_app.config["FAST_DEMO"],
        )
    else:
        run.active_status = "skipped"
        run.active_pct = 100

        with open(run.active_path, "w", encoding="utf-8") as file:
            file.write("Active scan skipped (no consent)\n==ACTIVE_DONE==\n")

    db.session.add(run)
    db.session.add(
        AuditEvent(
            event_type="run_start",
            message="Run started",
            vendor_id=vendor.id,
            run_id=run.id,
        )
    )
    db.session.commit()

    flash("Run started.", "success")
    return redirect(url_for("main.vendor_detail", vendor_id=vendor.id))


def _tail(path, n=80):
    try:
        with open(path, "r", encoding="utf-8") as file:
            lines = file.readlines()

        return "".join(lines[-n:])

    except Exception:
        return ""


def _update_from_log(run, kind):
    path = run.passive_path if kind == "passive" else run.active_path
    parser = parse_passive_line if kind == "passive" else parse_active_line
    sentinel = "==PASSIVE_DONE==" if kind == "passive" else "==ACTIVE_DONE=="

    total_lines = 0
    done = False

    try:
        with open(path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, 1):
                total_lines = line_number

                if sentinel in line:
                    done = True

                item = parser(line)

                if item:
                    exists = Finding.query.filter_by(
                        run_id=run.id,
                        description=item["description"],
                    ).first()

                    if not exists:
                        db.session.add(
                            Finding(
                                run_id=run.id,
                                severity=item["severity"],
                                category=item["category"],
                                description=item["description"],
                            )
                        )

    except Exception:
        pass

    pct = min(99, int(total_lines / 3.0))

    if done:
        pct = 100

    if kind == "passive":
        run.passive_pct = pct
        run.passive_log = _tail(path)

        if done:
            run.passive_status = "completed"

    else:
        if run.active_status != "skipped":
            run.active_pct = pct
            run.active_log = _tail(path)

            if done:
                run.active_status = "completed"


@main_bp.route("/api/run_status/<int:run_id>")
@login_required
def api_run_status(run_id):
    run = db.session.get(ScanRun, run_id)

    if not run:
        return jsonify({"error": "not found"}), 404

    if run.passive_status == "running":
        _update_from_log(run, "passive")

    if run.active_status == "running":
        _update_from_log(run, "active")

    if (
        run.passive_status in ("completed", "skipped")
        and run.active_status in ("completed", "skipped")
        and run.status != "completed"
    ):
        run.status = "completed"
        run.completed_at = dt.datetime.utcnow()

        p10, p50, p90, _ = run_simulation(
            run,
            trials=current_app.config.get("MC_TRIALS", 10000),
            seed=None,
        )

        run.p10 = p10
        run.p50 = p50
        run.p90 = p90

        path = build_report(run)

        db.session.add(
            AuditEvent(
                event_type="run_complete",
                message="Run completed",
                vendor_id=run.vendor_id,
                run_id=run.id,
                details={"report": path},
            )
        )

    db.session.commit()

    findings = [
    {
        "severity": f.severity or "low",
        "category": f.category or "info",
        "description": f.description or ""
    }
    for f in run.findings
    ]

    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}

    for f in run.findings:
        s = (f.severity or "low").lower()
        if s in counts:
            counts[s] += 1
    return jsonify({
        'status': run.status,
        'passive': {
            'status': run.passive_status,
            'pct': run.passive_pct,
            'tail': run.passive_log
        },
        'active': {
            'status': run.active_status,
            'pct': run.active_pct,
            'tail': run.active_log
        },
        'fair': {
            'p10': run.p10,
            'p50': run.p50,
            'p90': run.p90
        },
        'findings': findings,
        'counts': counts
    })


@main_bp.route("/runs")
@login_required
def runs():
    runs = ScanRun.query.order_by(ScanRun.started_at.desc()).all()
    return render_template("runs.html", runs=runs)


@main_bp.route("/run/detail/<int:run_id>")
@login_required
def run_detail(run_id):
    run = db.session.get(ScanRun, run_id)

    if not run:
        flash("Run not found", "danger")
        return redirect(url_for("main.runs"))

    findings = Finding.query.filter_by(run_id=run.id).order_by(Finding.id.desc()).all()
    counts = _count_findings(findings)

    return render_template("run_detail.html", run=run, findings=findings, counts=counts)


@main_bp.route("/report/<int:run_id>")
@login_required
def download_report(run_id):
    run = db.session.get(ScanRun, run_id)

    if not run:
        abort(404)

    if run.run_path and os.path.isabs(run.run_path):
        base = run.run_path
    elif run.run_path:
        base = os.path.abspath(os.path.join(os.getcwd(), run.run_path))
    else:
        base = os.path.abspath(
            os.path.join(os.getcwd(), "data", "runs", "_orphan", str(run_id))
        )

    os.makedirs(base, exist_ok=True)

    preferred = os.path.join(base, "_reports", "report.md")
    legacy = os.path.join(base, "report.md")

    path = preferred if os.path.exists(preferred) else legacy

    if not os.path.exists(path):
        path = build_report(run)

    if not os.path.exists(path):
        abort(404)

    return send_file(
        os.path.abspath(path),
        mimetype="text/markdown",
        as_attachment=True,
        download_name=f"report_run_{run.id}.md",
        max_age=0,
    )