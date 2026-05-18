"""
Crypto Inventory Demo
---------------------

Purpose:
Demonstrate how an application or security team can *discover and classify*
cryptographic usage from a quantum-readiness perspective.

This demo focuses on:
- TLS certificate signature algorithms
- Public key types and sizes
- Classification into quantum-vulnerable vs PQC-ready (future)

This is NOT a scanner or production tool.
It is a conceptual demo aligned with real PQC migration workflows.
"""

import ssl
import socket
from pprint import pprint

# -----------------------------
# Configuration
# -----------------------------
TARGET_HOST = "example.com"
TARGET_PORT = 443

# Algorithms considered quantum-vulnerable
QUANTUM_VULNERABLE_SIGS = {
    "rsa",
    "ecdsa"
}

# -----------------------------
# Helper functions
# -----------------------------

def fetch_tls_certificate(host: str, port: int):
    """Fetch peer certificate from a TLS endpoint."""
    context = ssl.create_default_context()

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()

    return cert, cipher

def classify_signature_algorithm(sig_alg):

    if sig_alg is None:
        return "Unknown (algorithm visibility unavailable)"

    sig_alg = sig_alg.lower()

    if "rsa" in sig_alg:
        return "Quantum-vulnerable"

    elif "ecdsa" in sig_alg:
        return "Quantum-vulnerable"

    elif "dilithium" in sig_alg:
        return "PQC-ready"

    elif "mldsa" in sig_alg:
        return "PQC-ready"

    elif "hybrid" in sig_alg:
        return "Hybrid"

    else:
        return "Unsupported / unclassified"
    
# -----------------------------
# Main demo logic
# -----------------------------

def main():
    print("\n=== Crypto Inventory Demo ===\n")
    print(f"Target: {TARGET_HOST}:{TARGET_PORT}\n")

    cert, cipher = fetch_tls_certificate(TARGET_HOST, TARGET_PORT)

    print(
        "\n[TLS Cipher Suite]: \n"
        f"   Algorithm    : {cipher[0]},\n "
        f"  TLS version   : {cipher[1]},\n"
        f"   Key size     : {cipher[2]} bits")

    subject = cert.get("subject")

    print("\n[Certificate Subject]:")
    for item in subject:
        for key, value in item:
            print(f"  {key}: {value}")

    sig_alg = cert.get("signatureAlgorithm")
    print("\n[Certificate Signature Algorithm]")

    if sig_alg:
        print(f"  Algorithm      : {sig_alg}")
    else:
        print("  Algorithm      : Not exposed by Python ssl API")
        print("  Reason         : TLS 1.3 / API visibility limitation\n")
    
    classification = classify_signature_algorithm(sig_alg)
    print("\n[Quantum Risk Assessment]")
    print(f"  Classification : ", classification)

    print("\n[Inventory Summary]")
    print(f"  Target Host            : {TARGET_HOST}")
    print(f"  Negotiated Cipher      : {cipher[0]}")
    print(f"  TLS Version            : {cipher[1]}")
    print(f"  Symmetric Key Size     : {cipher[2]} bits")
    print(f"  Signature Algorithm    : {sig_alg}")
    print(f"  Quantum Risk           : {classification}")
if __name__ == "__main__":
    main()
