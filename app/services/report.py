import os

def build_report(run):
    # Always write to /reports/report.md
    base = run.run_path or os.path.join('data', 'runs', '_orphan', str(getattr(run, 'id', 'unknown')))
    out_dir = os.path.abspath(os.path.join(base, "_reports"))
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "report.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# FAIR Risk Report\n\nVendor: {run.vendor.name}\n\n")
        if run.p50 is not None:
            f.write(f"P10: {run.p10:,.2f}\n\nP50: {run.p50:,.2f}\n\nP90: {run.p90:,.2f}\n\n")
        f.write("## Findings\n")
        for fd in run.findings:
            f.write(f"- [{(fd.severity or 'low').upper()}] {fd.category}: {fd.description}\n")
    return path
