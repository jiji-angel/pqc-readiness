"""
Hybrid Certificate Demonstration
--------------------------------

This program demonstrates a hybrid PKI model used during
post-quantum cryptography (PQC) migration.

The certificate contains:
1. A classical signature (ECDSA)
2. A simulated PQC signature

Security goal:
- Trust remains valid as long as at least ONE
  signature algorithm remains secure.
"""

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature


# ============================================================
# Simulated PQC Signature Scheme
# ============================================================

def pqc_generate_keypair():
    """
    Simulated PQC keypair generation.

    NOTE:
    This is NOT a real PQC implementation.
    It models the architecture only.
    """

    private_key = os.urandom(32)
    public_key = private_key

    return private_key, public_key


def pqc_sign(message: bytes, private_key: bytes) -> bytes:
    """
    Simulated PQC signing operation.
    """

    digest = hashes.Hash(hashes.SHA256())
    digest.update(private_key)
    digest.update(message)

    return digest.finalize()


def pqc_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Simulated PQC verification.
    """

    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key)
    digest.update(message)

    expected_signature = digest.finalize()

    return expected_signature == signature


# ============================================================
# Classical PKI
# ============================================================

def generate_classical_root():
    print("[+] Generating classical Root CA")

    private_key = ec.generate_private_key(ec.SECP256R1())

    return private_key, private_key.public_key()


def generate_leaf_key():
    print("[+] Generating leaf certificate keypair")

    private_key = ec.generate_private_key(ec.SECP256R1())

    return private_key, private_key.public_key()


# ============================================================
# Hybrid Certificate Creation
# ============================================================

def create_hybrid_certificate(
    root_classical_private_key,
    root_pqc_private_key,
    leaf_public_key
):
    print("[+] Creating hybrid certificate")

    leaf_public_bytes = leaf_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # --------------------------------------------------------
    # Classical ECDSA signature
    # --------------------------------------------------------

    digest = hashes.Hash(hashes.SHA256())
    digest.update(leaf_public_bytes)

    hashed_leaf_key = digest.finalize()

    classical_signature = root_classical_private_key.sign(
        hashed_leaf_key,
        ec.ECDSA(Prehashed(hashes.SHA256()))
    )

    # --------------------------------------------------------
    # Simulated PQC signature
    # --------------------------------------------------------

    pqc_signature = pqc_sign(
        leaf_public_bytes,
        root_pqc_private_key
    )

    certificate = {
        "leaf_public_key": leaf_public_bytes,
        "classical_signature": classical_signature,
        "pqc_signature": pqc_signature,
    }

    return certificate


# ============================================================
# Hybrid Certificate Verification
# ============================================================

def verify_hybrid_certificate(
    certificate,
    root_classical_public_key,
    root_pqc_public_key
):
    print("\n[+] Verifying hybrid certificate")

    leaf_public_bytes = certificate["leaf_public_key"]

    # --------------------------------------------------------
    # Verify classical signature
    # --------------------------------------------------------

    digest = hashes.Hash(hashes.SHA256())
    digest.update(leaf_public_bytes)

    hashed_leaf_key = digest.finalize()

    classical_valid = False

    try:
        root_classical_public_key.verify(
            certificate["classical_signature"],
            hashed_leaf_key,
            ec.ECDSA(Prehashed(hashes.SHA256()))
        )

        classical_valid = True
        print("    [✓] Classical signature valid")

    except InvalidSignature:
        print("    [✗] Classical signature INVALID")

    # --------------------------------------------------------
    # Verify PQC signature
    # --------------------------------------------------------

    pqc_valid = pqc_verify(
        leaf_public_bytes,
        certificate["pqc_signature"],
        root_pqc_public_key
    )

    if pqc_valid:
        print("    [✓] PQC signature valid")
    else:
        print("    [✗] PQC signature INVALID")

    # --------------------------------------------------------
    # Hybrid trust policy
    # --------------------------------------------------------

    print("\n[Hybrid Trust Policy]")

    if classical_valid or pqc_valid:
        print("    Certificate TRUSTED")
        print("    Reason: At least one signature verified")
    else:
        print("    Certificate REJECTED")
        print("    Reason: Both signatures failed")


# ============================================================
# Main Demo
# ============================================================

def main():

    print("\n=== Hybrid Certificate Demo ===\n")

    # Root CA keys
    root_classical_private_key, root_classical_public_key = (
        generate_classical_root()
    )

    root_pqc_private_key, root_pqc_public_key = (
        pqc_generate_keypair()
    )

    # Leaf certificate key
    _, leaf_public_key = generate_leaf_key()

    # Create hybrid certificate
    certificate = create_hybrid_certificate(
        root_classical_private_key,
        root_pqc_private_key,
        leaf_public_key
    )

    # Verify hybrid certificate
    verify_hybrid_certificate(
        certificate,
        root_classical_public_key,
        root_pqc_public_key
    )

    print("\n=== Demo Complete ===\n")


if __name__ == "__main__":
    main()
