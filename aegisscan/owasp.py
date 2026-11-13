"""OWASP Top 10:2025 mapping, by CWE.

The category for a finding is looked up from its CWE, using the "List of Mapped
CWEs" on each official category page (https://owasp.org/Top10/2025/). Keeping
the table in one place means a check and its findings cannot disagree, and a
CWE that is not in the table fails loudly when the check is registered.
"""

from __future__ import annotations

EDITION = "2025"

CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

# Only the CWEs AegisScan reports. Each entry was read from the mapped-CWE list of the
# category page named on the right.
_CWE_TO_CATEGORY = {
    # A01:2025 Broken Access Control
    "CWE-200": "A01",  # Exposure of Sensitive Information to an Unauthorized Actor
    "CWE-538": "A01",  # Insertion of Sensitive Information into Externally-Accessible File
    "CWE-548": "A01",  # Exposure of Information Through Directory Listing
    "CWE-552": "A01",  # Files or Directories Accessible to External Parties
    "CWE-1275": "A01",  # Sensitive Cookie with Improper SameSite Attribute
    # A02:2025 Security Misconfiguration
    "CWE-614": "A02",  # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    "CWE-942": "A02",  # Permissive Cross-domain Policy with Untrusted Domains
    "CWE-1004": "A02",  # Sensitive Cookie Without 'HttpOnly' Flag
    # A04:2025 Cryptographic Failures
    "CWE-319": "A04",  # Cleartext Transmission of Sensitive Information
    "CWE-326": "A04",  # Inadequate Encryption Strength
    "CWE-327": "A04",  # Use of a Broken or Risky Cryptographic Algorithm
    "CWE-328": "A04",  # Use of Weak Hash
    # A06:2025 Insecure Design
    "CWE-693": "A06",  # Protection Mechanism Failure
    "CWE-1021": "A06",  # Improper Restriction of Rendered UI Layers or Frames
    # A07:2025 Authentication Failures
    "CWE-290": "A07",  # Authentication Bypass by Spoofing
    "CWE-295": "A07",  # Improper Certificate Validation
    "CWE-297": "A07",  # Improper Validation of Certificate with Host Mismatch
    "CWE-298": "A07",  # Improper Validation of Certificate Expiration
    "CWE-350": "A07",  # Reliance on Reverse DNS Resolution for a Security-Critical Action
    # A10:2025 Mishandling of Exceptional Conditions
    "CWE-209": "A10",  # Generation of Error Message Containing Sensitive Information
}

# CWEs that no 2025 category lists. They are mapped through their parent in the CWE
# hierarchy, which is listed.
_VIA_PARENT = {
    "CWE-527": "CWE-552",  # Exposure of Version-Control Repository to an Unauthorized Sphere
    "CWE-530": "CWE-552",  # Exposure of Backup File to an Unauthorized Control Sphere
}


def label(code: str) -> str:
    """'A02' -> 'A02:2025 Security Misconfiguration'."""
    return f"{code}:{EDITION} {CATEGORIES[code]}"


def category_for(cwe: str) -> str | None:
    """The OWASP Top 10:2025 category a CWE is mapped to, or None if it is not mapped."""
    cwe = _VIA_PARENT.get(cwe, cwe)
    code = _CWE_TO_CATEGORY.get(cwe)
    return label(code) if code else None
