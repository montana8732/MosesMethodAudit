import os
import re
import sqlite3
import csv
import io
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, Response, redirect, url_for

# Load environment variables from .env file
load_dotenv()

# Pull secret key from .env (defaults to MOSES_METHOD_SECRET_KEY_2026)
API_KEY = os.getenv("SECRET_KEY", os.getenv("API_KEY", "MOSES_METHOD_SECRET_KEY_2026"))

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('audit_logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT,
            violations_count INTEGER,
            log_text TEXT,
            redacted_text TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def scan_and_redact(text):
    findings = []
    redacted = text

    # 1. Social Security Numbers (SSN)
    if re.search(r'\b\d{3}-\d{2}-\d{4}\b', redacted):
        findings.append("CRITICAL: Potential Social Security Number (PII) detected.")
        redacted = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]', redacted)

    # 2. National Provider Identifier (NPI)
    if re.search(r'\b[12]\d{9}\b', redacted):
        findings.append("WARNING: Potential NPI Provider Identifier (PHI) detected.")
        redacted = re.sub(r'\b[12]\d{9}\b', '[REDACTED-NPI]', redacted)

    # 3. Medical Record Number with Optional Lead-in Prefix
    if re.search(r'\b(patient\s+)?MRN[-:\s]?\d{6,8}\b', redacted, re.IGNORECASE):
        findings.append("CRITICAL: Potential Medical Record Number (MRN/PHI) detected.")
        redacted = re.sub(r'\b(patient\s+)?MRN[-:\s]?\d{6,8}\b', '[REDACTED-MRN]', redacted, flags=re.IGNORECASE)

    # 4. ICD-10 Coding Standard with Optional Lead-in Prefix
    if re.search(r'\b(ICD-10(\s+code)?\s+)?[A-TV-Z][0-9][0-9A-B](\.[0-9A-TV-Z]{1,4})?\b', redacted, re.IGNORECASE):
        findings.append("CRITICAL: Potential ICD-10 Clinical Diagnosis Code (PHI) detected.")
        redacted = re.sub(r'\b(ICD-10(\s+code)?\s+)?[A-TV-Z][0-9][0-9A-B](\.[0-9A-TV-Z]{1,4})?\b', '[REDACTED-ICD10]', redacted, flags=re.IGNORECASE)

    # 5. Email Addresses
    if re.search(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', redacted):
        findings.append("WARNING: Potential Email Address (PII) detected.")
        redacted = re.sub(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', '[REDACTED-EMAIL]', redacted)

    # 6. Phone Numbers
    if re.search(r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b', redacted):
        findings.append("WARNING: Potential Phone Number detected in unencrypted log.")
        redacted = re.sub(r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b', '[REDACTED-PHONE]', redacted)

    # 7. Remaining Standalone Medical Keywords
    medical_keywords = ["diagnosis", "prescription", "patient", "dob", "icd-10", "cpt"]
    for word in medical_keywords:
        pattern = re.compile(r'\b' + re.escape(word) + r'\b', re.IGNORECASE)
        if pattern.search(redacted):
            findings.append(f"CRITICAL: Unprotected medical/clinical keyword '{word}' detected.")
            redacted = pattern.sub('[REDACTED-PHI]', redacted)

    return findings, redacted

def log_to_db(status, count, raw_text, redacted_text):
    conn = sqlite3.connect('audit_logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_logs (status, violations_count, log_text, redacted_text)
        VALUES (?, ?, ?, ?)
    ''', (status, count, raw_text, redacted_text))
    conn.commit()
    conn.close()

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        text_to_scan = request.form.get('log_data', '')
        audit_results, sanitized_text = scan_and_redact(text_to_scan)
        status = "FAILED COMPLIANCE" if audit_results else "PASSED"
        
        log_to_db(status, len(audit_results), text_to_scan, sanitized_text)
        
        result = {
            "status": status,
            "violations": audit_results,
            "sanitized": sanitized_text
        }

    conn = sqlite3.connect('audit_logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, timestamp, status, violations_count, log_text, redacted_text FROM audit_logs ORDER BY id DESC LIMIT 5')
    recent_logs = cursor.fetchall()
    conn.close()

    return render_template('index.html', result=result, recent_logs=recent_logs)

@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect('audit_logs.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM audit_logs')
    total_audits = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'PASSED'")
    passed_audits = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'FAILED COMPLIANCE'")
    failed_audits = cursor.fetchone()[0]
    
    cursor.execute('SELECT SUM(violations_count) FROM audit_logs')
    total_violations = cursor.fetchone()[0] or 0
    
    conn.close()
    
    pass_rate = round((passed_audits / total_audits * 100), 1) if total_audits > 0 else 100.0

    return render_template('dashboard.html', 
                           total_audits=total_audits, 
                           passed_audits=passed_audits, 
                           failed_audits=failed_audits, 
                           total_violations=total_violations, 
                           pass_rate=pass_rate)

@app.route('/docs')
def api_docs():
    return render_template('docs.html')

@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    conn = sqlite3.connect('audit_logs.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM audit_logs')
    conn.commit()
    conn.close()
    return redirect(url_for('home'))

@app.route('/export')
def export_csv():
    conn = sqlite3.connect('audit_logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, timestamp, status, violations_count, log_text, redacted_text FROM audit_logs ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Record ID', 'Timestamp', 'Compliance Status', 'Violations Count', 'Raw Log Entry', 'Sanitized Log Entry'])
    
    for row in rows:
        writer.writerow(row)

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=MosesMethod_Audit_Report.csv"}
    )

@app.route('/audit', methods=['POST'])
def run_audit():
    client_key = request.headers.get('X-API-KEY')
    if not client_key or client_key != API_KEY:
        return jsonify({"error": "Unauthorized: Invalid or missing X-API-KEY header"}), 401

    data = request.json
    if not data or 'log_data' not in data:
        return jsonify({"error": "No log_data provided"}), 400
    
    text_to_scan = data['log_data']
    audit_results, sanitized_text = scan_and_redact(text_to_scan)
    status = "FAILED COMPLIANCE" if audit_results else "PASSED"
    
    log_to_db(status, len(audit_results), text_to_scan, sanitized_text)
    
    report = {
        "agency": "The Moses Method Structures, LLC",
        "audit_type": "Healthcare AI Bot Log Scan",
        "compliance_status": status,
        "total_violations": len(audit_results),
        "violation_details": audit_results,
        "sanitized_log": sanitized_text
    }
    
    return jsonify(report)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
