"""
PQC Leaf Certificate Demonstration
----------------------------------

This demo models a realistic post-quantum PKI migration strategy:

    Classical Root CA
            ↓
    Classical Intermediate CA
            ↓
    PQC-enabled Leaf Certificate

Why this matters:
- Root certificates are difficult to replace
- Leaf certificates rotate more frequently
- PQC adoption is expected to begin at the edge

This program focuses on migration architecture,
not real PQC algorithm implementations.
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
# Classical PKI Components
# ============================================================

def generate_classical_ca(name):
    print(f"[+] Generating classical CA: {name}")

    private_key = ec.generate_private_key(ec.SECP256R1())

    return private_key, private_key.public_key()


def generate_pqc_leaf():
    print("[+] Generating PQC leaf certificate keypair")

    return pqc_generate_keypair()


# ============================================================
# Classical Certificate Signing
# ============================================================

def classical_sign(public_key_bytes, signer_private_key):
    """
    Classical ECDSA signing.
    """

    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key_bytes)

    hashed = digest.finalize()

    signature = signer_private_key.sign(
        hashed,
        ec.ECDSA(Prehashed(hashes.SHA256()))
    )

    return signature


def classical_verify(public_key_bytes, signature, signer_public_key):
    """
    Classical ECDSA verification.
    """

    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key_bytes)

    hashed = digest.finalize()

    try:
        signer_public_key.verify(
            signature,
            hashed,
            ec.ECDSA(Prehashed(hashes.SHA256()))
        )

        return True

    except InvalidSignature:
        return False


# ============================================================
# Main Demo
# ============================================================

def main():

    print("\n=== PQC Leaf Certificate Demo ===\n")

    # --------------------------------------------------------
    # Root CA
    # --------------------------------------------------------

    root_private_key, root_public_key = (
        generate_classical_ca("Root CA")
    )

    # --------------------------------------------------------
    # Intermediate CA
    # --------------------------------------------------------

    intermediate_private_key, intermediate_public_key = (
        generate_classical_ca("Intermediate CA")
    )

    # Serialize intermediate public key
    intermediate_public_bytes = (
        intermediate_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # Root signs intermediate
    print("[+] Root CA signing Intermediate CA")

    intermediate_signature = classical_sign(
        intermediate_public_bytes,
        root_private_key
    )

    # --------------------------------------------------------
    # PQC Leaf Certificate
    # --------------------------------------------------------

    pqc_leaf_private_key, pqc_leaf_public_key = (
        generate_pqc_leaf()
    )

    # Intermediate signs PQC leaf
    print("[+] Intermediate CA signing PQC leaf certificate")

    pqc_leaf_signature = classical_sign(
        pqc_leaf_public_key,
        intermediate_private_key
    )

    # --------------------------------------------------------
    # Verification Phase
    # --------------------------------------------------------

    print("\n[Verification Phase]")

    # Verify Intermediate CA
    intermediate_valid = classical_verify(
        intermediate_public_bytes,
        intermediate_signature,
        root_public_key
    )

    if intermediate_valid:
        print("    [✓] Intermediate CA trusted by Root CA")
    else:
        print("    [✗] Intermediate CA verification FAILED")

    # Verify PQC leaf
    pqc_leaf_valid = classical_verify(
        pqc_leaf_public_key,
        pqc_leaf_signature,
        intermediate_public_key
    )

    if pqc_leaf_valid:
        print("    [✓] PQC leaf certificate trusted")
    else:
        print("    [✗] PQC leaf verification FAILED")

    # --------------------------------------------------------
    # Migration Explanation
    # --------------------------------------------------------

    print("\n[Migration Model]")

    print("    Root CA          : Classical")
    print("    Intermediate CA  : Classical")
    print("    Leaf Certificate : PQC-enabled")

    print("\n[Why This Strategy Works]")

    print("    - Root certificates are long-lived")
    print("    - Leaf certificates rotate frequently")
    print("    - PQC can be introduced incrementally")
    print("    - Existing trust anchors remain usable")

    print("\n=== Demo Complete ===\n")


if __name__ == "__main__":
    main()
