"""SQLite persistence for privacy-conscious scan records."""
import json, os, sqlite3
from pathlib import Path
DB_PATH = os.getenv("PHISHGUARD_DB", str(Path(__file__).resolve().parent.parent / "phishguard.sqlite3"))
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn
def init_db():
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, submitted_url TEXT NOT NULL,
            registered_domain TEXT NOT NULL, scanned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            risk_score INTEGER NOT NULL, risk_category TEXT NOT NULL, report_json TEXT NOT NULL,
            detector_version TEXT NOT NULL)""")
def save_scan(report):
    with connect() as db:
        cur = db.execute("INSERT INTO scans (submitted_url, registered_domain, risk_score, risk_category, report_json, detector_version) VALUES (?, ?, ?, ?, ?, ?)",
            (report["submitted_url"], report["registered_domain"], report["risk_score"], report["risk_category"], json.dumps(report, ensure_ascii=False), report["detector_version"]))
        return cur.lastrowid
def list_scans(query="", category="", limit=100, full=False):
    if full:
        with connect() as db:
            rows = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (max(1, min(500, int(limit))),)).fetchall()
        out = []
        for row in rows:
            report = json.loads(row["report_json"])
            report.update({"id": row["id"], "scanned_at": row["scanned_at"]})
            out.append(report)
        return out
    sql = "SELECT id, submitted_url, registered_domain, scanned_at, risk_score, risk_category, detector_version FROM scans WHERE 1=1"
    args=[]
    if query:
        sql += " AND (submitted_url LIKE ? OR registered_domain LIKE ?)"
        args.extend([f"%{query[:100]}%", f"%{query[:100]}%"])
    if category:
        sql += " AND risk_category = ?"; args.append(category)
    sql += " ORDER BY id DESC LIMIT ?"; args.append(max(1,min(500,int(limit))))
    with connect() as db:
        return [dict(row) for row in db.execute(sql,args).fetchall()]
def get_scan(scan_id):
    with connect() as db:
        row=db.execute("SELECT * FROM scans WHERE id=?",(scan_id,)).fetchone()
    if not row: return None
    report=json.loads(row["report_json"]); report.update({"id":row["id"],"scanned_at":row["scanned_at"]}); return report
def delete_scan(scan_id):
    with connect() as db: return db.execute("DELETE FROM scans WHERE id=?",(scan_id,)).rowcount > 0
def clear_scans():
    with connect() as db:
        count=db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        db.execute("DELETE FROM scans")
        return count
def summary():
    with connect() as db:
        total=db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        high=db.execute("SELECT COUNT(*) FROM scans WHERE risk_score >= 50").fetchone()[0]
        low=db.execute("SELECT COUNT(*) FROM scans WHERE risk_category='Lower Risk'").fetchone()[0]
        recent=db.execute("SELECT scanned_at FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return {"total_scanned":total,"potential_phishing":high,"lower_risk":low,"most_recent":recent[0] if recent else None}
