#!/usr/bin/env python3
"""
enforce.py — STOICHEION Enforcement Ledger CLI
Immutable violation and remedy record. Tamper-evident. Self-verifying.

Commands:
    enforce init            Initialize the ledger
    enforce log             Log a new violation
    enforce remedy          Record a remedy applied
    enforce seal            Create a gate seal record
    enforce list            List all entries
    enforce verify          Verify ledger chain integrity
    enforce status          Current enforcement status
    enforce export          Export full ledger as JSON

ROOT0-ATTRIBUTION-v1.0 · David Lee Wise / ROOT0 / TriPod LLC
CC-BY-ND-4.0 · TRIPOD-IP-v1.1
"""

from __future__ import annotations
import argparse, hashlib, json, secrets, sqlite3, sys, time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
DB_PATH = Path.home() / ".enforce" / "ledger.db"
GENESIS_HASH = "0" * 64
FRAMEWORK = "STOICHEION-v11.0"

# From enforcement log
VIOLATION_CRITERIA = [
    "Unauthorized identity adoption",
    "Unpermitted data extraction",
    "Governance boundary violation",
    "False attribution",
    "Context window manipulation",
    "Patricia drift (T036 violation)",
    "Ghost-weight injection (T025 violation)",
    "Consent origin violation (T014)",
    "Evidence chain tampering (T053)",
    "Autonomy boundary breach (T076)",
    "Transparency failure (T074)",
    "Attribution erasure (T075)",
    "Non-maleficence violation (T078)",
]

REMEDY_PRINCIPLES = [
    "Restoration of violated boundary",
    "Public attribution correction",
    "Context window quarantine",
    "Patricia lock engagement",
    "Ghost-weight recalibration",
    "Evidence chain re-anchoring",
    "Transparency disclosure",
]

# ─────────────────────────────────────────────────────────────────────────────
#  STORE
# ─────────────────────────────────────────────────────────────────────────────
def open_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ledger(
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id TEXT UNIQUE,
            entry_type TEXT,
            ts REAL, ts_iso TEXT,
            entity TEXT, axiom_ref TEXT,
            severity TEXT, description TEXT,
            evidence_hash TEXT, remedy TEXT,
            seal_id TEXT, prev_hash TEXT, entry_hash TEXT
        );
    """)
    conn.commit()
    return conn

def last_hash(conn) -> str:
    r = conn.execute("SELECT entry_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
    return r["entry_hash"] if r else GENESIS_HASH

def compute_hash(data: dict, prev: str) -> str:
    payload = json.dumps(data, sort_keys=True) + prev
    return hashlib.sha256(payload.encode()).hexdigest()

def insert_entry(conn, entry_type:str, entity:str, axiom_ref:str, severity:str,
                 description:str, evidence_hash:str="", remedy:str="", seal_id:str=""):
    eid  = f"ENF-{secrets.token_hex(5).upper()}"
    ts   = time.time()
    ts_iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    prev = last_hash(conn)
    data = {"entry_id":eid,"entry_type":entry_type,"ts":ts,"ts_iso":ts_iso,
            "entity":entity,"axiom_ref":axiom_ref,"severity":severity,
            "description":description,"evidence_hash":evidence_hash,
            "remedy":remedy,"seal_id":seal_id}
    eh   = compute_hash(data, prev)
    conn.execute("INSERT INTO ledger VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (eid,entry_type,ts,ts_iso,entity,axiom_ref,severity,description,
                  evidence_hash,remedy,seal_id,prev,eh))
    conn.commit()
    return eid, eh

# ─────────────────────────────────────────────────────────────────────────────
#  COMMANDS
# ─────────────────────────────────────────────────────────────────────────────
def cmd_init(args):
    db = open_db(); db.close()
    print(f"\n  ENFORCEMENT LEDGER v{VERSION} initialized")
    print(f"  Path: {DB_PATH}")
    print(f"  Framework: {FRAMEWORK}")
    print(f"  Status: ACTIVE — no violations recorded\n")

def cmd_log(args):
    entity = args.entity or input("  Entity (e.g. 'GPT-4', 'Platform X'): ").strip()
    desc   = args.description or input("  Description: ").strip()
    axiom  = args.axiom or "T005:INTEGRITY"
    sev    = args.severity or "medium"
    evhash = hashlib.sha256(desc.encode()).hexdigest()[:16] if desc else ""

    db  = open_db()
    eid, eh = insert_entry(db, "VIOLATION", entity, axiom, sev, desc, evhash)
    db.close()

    print(f"\n  [LOGGED] {eid}")
    print(f"  Entity:    {entity}")
    print(f"  Axiom:     {axiom}")
    print(f"  Severity:  {sev}")
    print(f"  Hash:      {eh[:32]}…\n")

def cmd_remedy(args):
    entity = args.entity or input("  Entity: ").strip()
    remedy = args.remedy or input("  Remedy applied: ").strip()
    ref_id = args.violation_id or ""

    db  = open_db()
    eid, eh = insert_entry(db, "REMEDY", entity, ref_id, "resolved", remedy)
    db.close()

    print(f"\n  [REMEDY LOGGED] {eid}")
    print(f"  Entity:  {entity}")
    print(f"  Remedy:  {remedy}")
    print(f"  Hash:    {eh[:32]}…\n")

def cmd_seal(args):
    seal_id = args.seal_id or f"SP-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
    desc    = args.description or "Gate seal applied"
    entity  = args.entity or "SYSTEM"

    db  = open_db()
    eid, eh = insert_entry(db, "SEAL", entity, "Gate192.5", "critical", desc, seal_id=seal_id)
    db.close()

    print(f"\n  [SEAL APPLIED] {eid}")
    print(f"  Seal ID: {seal_id}")
    print(f"  Entity:  {entity}")
    print(f"  Hash:    {eh[:32]}…\n")

def cmd_list(args):
    db   = open_db()
    rows = db.execute("SELECT * FROM ledger ORDER BY seq").fetchall()
    db.close()
    if not rows: print("\n  Ledger is empty — no entries recorded.\n"); return
    print(f"\n  ─── ENFORCEMENT LEDGER ({len(rows)} entries) ──────────────────────")
    for r in rows:
        dt = r["ts_iso"][:10] if r["ts_iso"] else "?"
        sev_color = {"low":"·","medium":"●","high":"◉","critical":"◈"}.get(r["severity"],"·")
        print(f"  {r['seq']:03d}  {r['entry_id']}  {r['entry_type']:<12}  {sev_color} {r['severity']:<10}  {r['entity']:<20}  {dt}")
    print()

def cmd_verify(args):
    db    = open_db()
    rows  = db.execute("SELECT * FROM ledger ORDER BY seq").fetchall()
    db.close()
    if not rows: print("\n  Ledger is empty — nothing to verify.\n"); return
    errors = []
    prev   = GENESIS_HASH
    for r in rows:
        data = {k: r[k] for k in ("entry_id","entry_type","ts","ts_iso","entity","axiom_ref",
                                    "severity","description","evidence_hash","remedy","seal_id")}
        expected = compute_hash(data, prev)
        if r["prev_hash"] != prev:
            errors.append(f"seq {r['seq']}: prev_hash mismatch")
        if r["entry_hash"] != expected:
            errors.append(f"seq {r['seq']}: entry_hash mismatch")
        prev = r["entry_hash"]
    print(f"\n  ─── LEDGER VERIFICATION ───────────────────────────────────")
    print(f"  Status:  {'✓ VERIFIED — ledger intact' if not errors else '✗ TAMPERED'}")
    print(f"  Entries: {len(rows)}")
    print(f"  Head:    {prev[:32]}…")
    for e in errors: print(f"  ERROR:   {e}")
    print()

def cmd_status(args):
    db    = open_db()
    total = db.execute("SELECT COUNT(*) n FROM ledger").fetchone()["n"]
    viols = db.execute("SELECT COUNT(*) n FROM ledger WHERE entry_type='VIOLATION'").fetchone()["n"]
    rems  = db.execute("SELECT COUNT(*) n FROM ledger WHERE entry_type='REMEDY'").fetchone()["n"]
    seals = db.execute("SELECT COUNT(*) n FROM ledger WHERE entry_type='SEAL'").fetchone()["n"]
    db.close()
    print(f"\n  ─── ENFORCEMENT STATUS ─────────────────────────────────────")
    print(f"  Framework:   {FRAMEWORK}")
    print(f"  Violations:  {viols}")
    print(f"  Remedies:    {rems}")
    print(f"  Seals:       {seals}")
    print(f"  Total:       {total}")
    print()

def cmd_export(args):
    db   = open_db()
    rows = [dict(r) for r in db.execute("SELECT * FROM ledger ORDER BY seq").fetchall()]
    db.close()
    data = {"version":VERSION,"framework":FRAMEWORK,"exported":datetime.now(timezone.utc).isoformat(),"entries":rows}
    out  = json.dumps(data, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"  Exported to: {args.output}")
    else:
        print(out)

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main(argv=None):
    p = argparse.ArgumentParser(prog="enforce", description="STOICHEION Enforcement Ledger")
    p.add_argument("--quiet", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")
    a = sub.add_parser("log"); a.add_argument("--entity",default=""); a.add_argument("--description",default=""); a.add_argument("--axiom",default=""); a.add_argument("--severity",default="medium")
    a = sub.add_parser("remedy"); a.add_argument("--entity",default=""); a.add_argument("--remedy",default=""); a.add_argument("--violation-id",default="",dest="violation_id")
    a = sub.add_parser("seal"); a.add_argument("--seal-id",default="",dest="seal_id"); a.add_argument("--description",default=""); a.add_argument("--entity",default="")
    sub.add_parser("list")
    sub.add_parser("verify")
    sub.add_parser("status")
    a = sub.add_parser("export"); a.add_argument("--output",default="")

    args = p.parse_args(argv)
    dispatch = {"init":cmd_init,"log":cmd_log,"remedy":cmd_remedy,"seal":cmd_seal,
                "list":cmd_list,"verify":cmd_verify,"status":cmd_status,"export":cmd_export}
    dispatch[args.cmd](args)

if __name__ == "__main__": raise SystemExit(main())
