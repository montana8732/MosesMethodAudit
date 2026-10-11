import os
import re
import json
import sqlite3
import hashlib
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, jsonify, Response

app = Flask(__name__)

DB_PATH = "audit_ledger.db"
SECRET_SALT = "MosesMethodSecureSalt2026!"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def calculate_row_hash(record_id, timestamp, actor_id, action, payload, prev_hash):
    raw_str = f"{record_id}|{timestamp}|{actor_id}|{action}|{payload}|{prev_hash}|{SECRET_SALT}"
    return hashlib.sha256(raw_str.encode('utf-8')).hexdigest()

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            action TEXT NOT NULL,
            payload TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def log_audit_event(actor_id, action, payload_dict):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, record_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    last_row = cursor.fetchone()
    
    if last_row:
        prev_hash = last_row["record_hash"]
        next_id = last_row["id"] + 1
    else:
        prev_hash = "0" * 64
        next_id = 1
        
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_json = json.dumps(payload_dict, sort_keys=True)
    
    record_hash = calculate_row_hash(next_id, timestamp, actor_id, action, payload_json, prev_hash)
    
    cursor.execute('''
        INSERT INTO audit_logs (id, timestamp, actor_id, action, payload, prev_hash, record_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (next_id, timestamp, actor_id, action, payload_json, prev_hash, record_hash))
    
    conn.commit()
    conn.close()
    return record_hash

def redact_sensitive_data(text):
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    redacted_text, ssn_count = re.subn(ssn_pattern, '[REDACTED_SSN]', text)
    
    npi_pattern = r'\b(?:NPI[:\s#]*)?([1-2]\d{9})\b'
    redacted_text, npi_count = re.subn(npi_pattern, '[REDACTED_NPI]', redacted_text, flags=re.IGNORECASE)

    icd10_pattern = r'\b[A-TV-Z][0-9][0-9A-Z](?:\.[0-9A-Z]{1,4})?\b'
    redacted_text, icd10_count = re.subn(icd10_pattern, '[REDACTED_ICD10]', redacted_text)

    mrn_pattern = r'\bMRN[:\s#]*[A-Z0-9-]{5,10}\b'
    redacted_text, mrn_count = re.subn(mrn_pattern, '[REDACTED_MRN]', redacted_text, flags=re.IGNORECASE)

    phi_terms = ['diagnosis', 'prescription', 'patient', 'medical history', 'treatment', 'dob']
    phi_count = 0
    for term in phi_terms:
        matches = re.findall(rf'\b{term}\b', redacted_text, flags=re.IGNORECASE)
        phi_count += len(matches)
        redacted_text = re.sub(rf'\b{term}\b', '[REDACTED_PHI]', redacted_text, flags=re.IGNORECASE)
        
    total_redactions = ssn_count + npi_count + icd10_count + mrn_count + phi_count
    return redacted_text, total_redactions, ssn_count, npi_count, icd10_count, mrn_count, phi_count

@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, timestamp, actor_id, action, payload, record_hash FROM audit_logs ORDER BY id DESC")
    logs = cursor.fetchall()
    
    total_audits = len(logs)
    compliant_scans = 0
    compliance_failures = 0
    total_redactions = 0
    
    cat_ssn = 0
    cat_npi = 0
    cat_icd10 = 0
    cat_mrn = 0
    cat_phi = 0
    
    for log in logs:
        try:
            payload = json.loads(log["payload"])
            if payload.get("compliance_status") == "COMPLIANT":
                compliant_scans += 1
            else:
                compliance_failures += 1
            total_redactions += payload.get("total_redactions", 0)
            
            cat_ssn += payload.get("ssn_count", 0)
            cat_npi += payload.get("npi_count", 0)
            cat_icd10 += payload.get("icd10_count", 0)
            cat_mrn += payload.get("mrn_count", 0)
            cat_phi += payload.get("phi_count", 0)
        except Exception:
            pass
            
    pass_rate = round((compliant_scans / total_audits * 100), 1) if total_audits > 0 else 100.0
    
    chart_data = {
        "compliant": compliant_scans,
        "failures": compliance_failures,
        "categories": ["SSN", "NPI", "ICD-10", "MRN", "PHI Terms"],
        "category_values": [cat_ssn, cat_npi, cat_icd10, cat_mrn, cat_phi]
    }
    
    conn.close()
    return render_template('dashboard.html', 
                           logs=logs, 
                           total_audits=total_audits,
                           compliant_scans=compliant_scans,
                           compliance_failures=compliance_failures,
                           total_redactions=total_redactions,
                           pass_rate=pass_rate,
                           chart_data=chart_data)

@app.route('/audit', methods=['POST'])
def run_audit():
    raw_log = request.form.get('log_data', '')
    active_actor = request.form.get('active_actor', 'web_ui_user')
    
    sanitized_text, total_redactions, ssn_count, npi_count, icd10_count, mrn_count, phi_count = redact_sensitive_data(raw_log)
    
    is_compliant = (total_redactions == 0)
    status_text = "COMPLIANT" if is_compliant else "REDACTED & FAILED COMPLIANCE"
    
    details = []
    if ssn_count > 0: details.append(f"CRITICAL: {ssn_count} SSN(s) masked.")
    if npi_count > 0: details.append(f"CRITICAL: {npi_count} NPI number(s) masked.")
    if icd10_count > 0: details.append(f"CRITICAL: {icd10_count} ICD-10 code(s) masked.")
    if mrn_count > 0: details.append(f"CRITICAL: {mrn_count} MRN identifier(s) masked.")
    if phi_count > 0: details.append(f"CRITICAL: {phi_count} PHI term(s) masked.")
    if is_compliant: details.append("PASS: Payload clean.")
        
    audit_payload = {
        "agency": "The Moses Method Structures, LLC",
        "audit_type": "Automated Redaction & Log Scan",
        "compliance_status": status_text,
        "sanitized_payload": sanitized_text,
        "total_violations": total_redactions,
        "total_redactions": total_redactions,
        "ssn_count": ssn_count,
        "npi_count": npi_count,
        "icd10_count": icd10_count,
        "mrn_count": mrn_count,
        "phi_count": phi_count,
        "violation_details": details
    }
    
    log_audit_event(active_actor, "PHI_REDACT_SCAN", audit_payload)
    return redirect(url_for('dashboard'))

@app.route('/api/audit/verify', methods=['GET'])
def verify_ledger():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, actor_id, action, payload, prev_hash, record_hash FROM audit_logs ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    
    expected_prev_hash = "0" * 64
    for row in rows:
        if row["prev_hash"] != expected_prev_hash:
            return jsonify({"status": "BREACH_DETECTED", "message": f"Broken Hash Chain link at Record ID {row['id']}!"}), 200
        computed_hash = calculate_row_hash(row["id"], row["timestamp"], row["actor_id"], row["action"], row["payload"], row["prev_hash"])
        if computed_hash != row["record_hash"]:
            return jsonify({"status": "BREACH_DETECTED", "message": f"Tampered Content detected at Record ID {row['id']}!"}), 200
        expected_prev_hash = row["record_hash"]
        
    return jsonify({"status": "VERIFIED", "message": "All records intact."}), 200

@app.route('/api/audit/tamper', methods=['POST'])
def simulate_tamper():
    actor = request.json.get('actor', 'unauthorized_actor') if request.is_json else 'unauthorized_actor'
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM audit_logs ORDER BY id ASC LIMIT 1")
    first_row = cursor.fetchone()
    if not first_row:
        conn.close()
        return jsonify({"status": "ERROR", "message": "No logs in database."}), 400
        
    tampered_payload = json.dumps({"agency": "UNAUTHORIZED_HACKER", "tampered": True, "breached_by": actor}, sort_keys=True)
    cursor.execute("UPDATE audit_logs SET payload = ? WHERE id = ?", (tampered_payload, first_row["id"]))
    conn.commit()
    conn.close()
    return jsonify({"status": "TAMPERED", "message": f"Record ID {first_row['id']} payload altered out-of-band!"})

@app.route('/api/audit/repair', methods=['POST'])
def repair_ledger():
    actor = request.json.get('actor', 'web_ui_user') if request.is_json else 'web_ui_user'
    
    # Enforce basic RBAC requirement for administrative repair
    if actor not in ['compliance_admin', 'sec_ops_lead']:
        return jsonify({"status": "UNAUTHORIZED", "message": f"Actor '{actor}' lacks ADMIN permissions to repair ledger!"}), 403

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, actor_id, action, payload FROM audit_logs ORDER BY id ASC")
    rows = cursor.fetchall()
    
    expected_prev_hash = "0" * 64
    repaired_count = 0
    for row in rows:
        computed_hash = calculate_row_hash(row["id"], row["timestamp"], row["actor_id"], row["action"], row["payload"], expected_prev_hash)
        cursor.execute("UPDATE audit_logs SET prev_hash = ?, record_hash = ? WHERE id = ?", (expected_prev_hash, computed_hash, row["id"]))
        expected_prev_hash = computed_hash
        repaired_count += 1
        
    conn.commit()
    conn.close()
    return jsonify({"status": "REPAIRED", "message": f"Re-signed {repaired_count} rows successfully."})

@app.route('/api/audit/export-csv', methods=['GET'])
def export_csv():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, actor_id, action, payload, record_hash FROM audit_logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    
    def generate():
        yield "ID,Timestamp_UTC,Actor_ID,Action,Sanitized_Payload,Record_SHA256_Hash\n"
        for row in rows:
            clean_payload = row["payload"].replace('"', '""')
            yield f'"{row["id"]}","{row["timestamp"]}","{row["actor_id"]}","{row["action"]}","{clean_payload}","{row["record_hash"]}"\n'
            
    return Response(generate(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=audit_ledger_report.csv"})

if __name__ == '__main__':
    app.run(port=5000, debug=True)
