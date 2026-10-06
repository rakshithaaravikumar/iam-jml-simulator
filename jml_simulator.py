"""IAM Joiner-Mover-Leaver (JML) Simulator
Processes HR events, assigns/removes access through role mappings (RBAC),
checks Segregation of Duties (SOD) and writes an audit log.
Uses dummy data only. Python 3 standard library."""
import csv, sqlite3, sys
from datetime import datetime

DB = "iam.db"

SCHEMA = """
DROP TABLE IF EXISTS users;  DROP TABLE IF EXISTS role_entitlements;
DROP TABLE IF EXISTS assignments; DROP TABLE IF EXISTS sod_rules; DROP TABLE IF EXISTS audit_log;
CREATE TABLE users(user_id TEXT PRIMARY KEY, name TEXT, dept TEXT, title TEXT, status TEXT);
CREATE TABLE role_entitlements(role TEXT, app TEXT, entitlement TEXT);
CREATE TABLE assignments(user_id TEXT, app TEXT, entitlement TEXT, source TEXT);
CREATE TABLE sod_rules(ent_a TEXT, ent_b TEXT, reason TEXT);
CREATE TABLE audit_log(ts TEXT, event TEXT, user_id TEXT, detail TEXT);
"""

# Role = department. Each role grants birthright entitlements.
ROLES = [
    ("Finance", "ERP", "Create_Vendor"), ("Finance", "ERP", "Approve_Payment"),
    ("Finance", "Email", "Mailbox"),
    ("IT", "AD", "VPN_Access"), ("IT", "AD", "Domain_User"), ("IT", "Email", "Mailbox"),
    ("HR", "HRMS", "View_Employee_Records"), ("HR", "Email", "Mailbox"),
]
SOD = [("Create_Vendor", "Approve_Payment", "Same person can create a vendor and approve its payment")]

def log(db, event, uid, detail):
    db.execute("INSERT INTO audit_log VALUES(?,?,?,?)",
               (datetime.now().isoformat(timespec="seconds"), event, uid, detail))

def grant_role(db, uid, dept):
    for app, ent in db.execute("SELECT app, entitlement FROM role_entitlements WHERE role=?", (dept,)).fetchall():
        db.execute("INSERT INTO assignments VALUES(?,?,?,?)", (uid, app, ent, "role:" + dept))
        log(db, "PROVISION", uid, f"{app}/{ent} via role {dept}")

def revoke_role_access(db, uid):
    """Deprovision role-based access only. Manual grants are NOT removed,
    which mimics a real-world gap that the reports below will catch."""
    rows = db.execute("SELECT app, entitlement FROM assignments WHERE user_id=? AND source LIKE 'role:%'", (uid,)).fetchall()
    for app, ent in rows:
        log(db, "DEPROVISION", uid, f"{app}/{ent}")
    db.execute("DELETE FROM assignments WHERE user_id=? AND source LIKE 'role:%'", (uid,))

def process(db, row):
    ev, uid = row["event"], row["user_id"]
    if ev == "join":
        db.execute("INSERT INTO users VALUES(?,?,?,?,'active')", (uid, row["name"], row["dept"], row["title"]))
        log(db, "JOINER", uid, f"{row['name']} joined {row['dept']}")
        grant_role(db, uid, row["dept"])
    elif ev == "move":
        old = db.execute("SELECT dept FROM users WHERE user_id=?", (uid,)).fetchone()[0]
        revoke_role_access(db, uid)
        db.execute("UPDATE users SET dept=?, title=? WHERE user_id=?", (row["dept"], row["title"], uid))
        log(db, "MOVER", uid, f"{old} -> {row['dept']}")
        grant_role(db, uid, row["dept"])
    elif ev == "leave":
        revoke_role_access(db, uid)
        db.execute("UPDATE users SET status='terminated' WHERE user_id=?", (uid,))
        log(db, "LEAVER", uid, "terminated, role access removed")

def sod_report(db):
    print("\n== SOD violations ==")
    found = False
    for a, b, why in db.execute("SELECT * FROM sod_rules").fetchall():
        for (uid,) in db.execute("""SELECT x.user_id FROM assignments x JOIN assignments y
            ON x.user_id=y.user_id WHERE x.entitlement=? AND y.entitlement=?""", (a, b)).fetchall():
            print(f"  {uid}: {a} + {b} ({why})"); found = True
    if not found: print("  none")

def leaver_report(db):
    print("\n== Leavers with residual access ==")
    rows = db.execute("""SELECT u.user_id, u.name, a.app, a.entitlement, a.source FROM users u
        JOIN assignments a ON a.user_id=u.user_id WHERE u.status='terminated'""").fetchall()
    for r in rows: print("  ", r)
    if not rows: print("  none")

def main():
    db = sqlite3.connect(DB)
    db.executescript(SCHEMA)
    db.executemany("INSERT INTO role_entitlements VALUES(?,?,?)", ROLES)
    db.executemany("INSERT INTO sod_rules VALUES(?,?,?)", SOD)
    with open("hr_events.csv") as f:
        for row in csv.DictReader(f):
            process(db, row)
        # Simulated mistake: someone granted access manually to a leaver.
        db.execute("INSERT INTO assignments VALUES('U103','HRMS','Admin_Console','manual')")
        log(db, "MANUAL_GRANT", "U103", "HRMS/Admin_Console (simulated gap)")
    db.commit()
    print("Active users:")
    for r in db.execute("SELECT user_id,name,dept,status FROM users"): print("  ", r)
    sod_report(db); leaver_report(db)
    print(f"\nAudit log entries: {db.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]} (see iam.db)")

if __name__ == "__main__":
    main()
