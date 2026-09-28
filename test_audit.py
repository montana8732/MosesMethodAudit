import unittest
from app import scan_and_redact

class TestComplianceRedaction(unittest.TestCase):

    def test_ssn_redaction(self):
        text = "SSN: 123-45-6789 should be masked."
        findings, redacted = scan_and_redact(text)
        self.assertIn("[REDACTED-SSN]", redacted)
        self.assertTrue(any("Social Security Number" in f for f in findings))

    def test_npi_redaction(self):
        text = "Provider NPI 1234567890 active."
        findings, redacted = scan_and_redact(text)
        self.assertIn("[REDACTED-NPI]", redacted)
        self.assertTrue(any("NPI Provider Identifier" in f for f in findings))

    def test_mrn_redaction(self):
        text = "Patient MRN-654321 logged."
        findings, redacted = scan_and_redact(text)
        self.assertIn("[REDACTED-MRN]", redacted)
        self.assertTrue(any("Medical Record Number" in f for f in findings))

    def test_icd10_redaction(self):
        text = "ICD-10 code E11.9 diagnosed."
        findings, redacted = scan_and_redact(text)
        self.assertIn("[REDACTED-ICD10]", redacted)
        self.assertTrue(any("ICD-10" in f for f in findings))

    def test_email_and_phone(self):
        text = "Contact doc@hospital.org or call 555-123-4567."
        findings, redacted = scan_and_redact(text)
        self.assertIn("[REDACTED-EMAIL]", redacted)
        self.assertIn("[REDACTED-PHONE]", redacted)

    def test_clean_text(self):
        text = "System backup completed with zero errors."
        findings, redacted = scan_and_redact(text)
        self.assertEqual(len(findings), 0)
        self.assertEqual(redacted, text)

if __name__ == '__main__':
    unittest.main()
