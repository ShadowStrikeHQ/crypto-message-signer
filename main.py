import argparse
import logging
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.exceptions import InvalidSignature

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the command-line argument parser.
    """
    parser = argparse.ArgumentParser(description="Sign and verify messages using cryptographic keys.")
    parser.add_argument("action", choices=["sign", "verify"], help="Action to perform: sign or verify.")
    parser.add_argument("--message", type=str, required=True, help="The message to sign or verify.")
    parser.add_argument("--private_key", type=str, help="Path to the private key file (for signing).")
    parser.add_argument("--public_key", type=str, help="Path to the public key file (for verifying).")
    parser.add_argument("--signature", type=str, help="Path to the signature file (for verification).")
    parser.add_argument("--algorithm", choices=["rsa", "ecdsa", "ed25519"], default="rsa", help="The signature algorithm to use (default: rsa).")
    parser.add_argument("--hash_algorithm", choices=["sha256", "sha384", "sha512"], default="sha256", help="The hash algorithm to use (default: sha256).")
    return parser.parse_args()

def load_key(key_path, is_private=True):
    """
    Loads a key (private or public) from a file.
    Handles file not found and key loading errors.
    """
    try:
        with open(key_path, "rb") as key_file:
            key_data = key_file.read()
    except FileNotFoundError:
        logging.error(f"Key file not found: {key_path}")
        sys.exit(1)  # Exit if file not found

    try:
        if is_private:
            private_key = load_pem_private_key(key_data, password=None)
            return private_key
        else:
            public_key = load_pem_public_key(key_data)
            return public_key
    except ValueError as e:
        logging.error(f"Error loading key from {key_path}: {e}")
        sys.exit(1)  # Exit if key loading fails

def sign_message(message, private_key_path, algorithm, hash_algorithm):
    """
    Signs a message using a private key.
    Supports RSA, ECDSA, and Ed25519 algorithms.
    """
    private_key = load_key(private_key_path, is_private=True)

    try:
        message_bytes = message.encode('utf-8')

        if algorithm == "rsa":
            if hash_algorithm == "sha256":
                h = hashes.SHA256()
            elif hash_algorithm == "sha384":
                h = hashes.SHA384()
            elif hash_algorithm == "sha512":
                h = hashes.SHA512()
            else:
                raise ValueError("Unsupported hash algorithm")
            signer = private_key.signer(
                serialization.BestAvailablePadding(),
                h
            )
            signer.update(message_bytes)
            signature = signer.finalize()

        elif algorithm == "ecdsa":
            if hash_algorithm == "sha256":
                h = hashes.SHA256()
            elif hash_algorithm == "sha384":
                h = hashes.SHA384()
            elif hash_algorithm == "sha512":
                h = hashes.SHA512()
            else:
                raise ValueError("Unsupported hash algorithm")

            signer = private_key.signer(ec.ECDSA(h))
            signer.update(message_bytes)
            signature = signer.finalize()


        elif algorithm == "ed25519":
            signature = private_key.sign(message_bytes)
        else:
            raise ValueError("Unsupported algorithm")

        return signature

    except Exception as e:
        logging.error(f"Error during signing: {e}")
        sys.exit(1)


def verify_message(message, public_key_path, signature_path, algorithm, hash_algorithm):
    """
    Verifies a message signature using a public key.
    Supports RSA, ECDSA, and Ed25519 algorithms.
    """
    public_key = load_key(public_key_path, is_private=False)

    try:
        with open(signature_path, "rb") as sig_file:
            signature = sig_file.read()
    except FileNotFoundError:
        logging.error(f"Signature file not found: {signature_path}")
        sys.exit(1)

    try:
        message_bytes = message.encode('utf-8')

        if algorithm == "rsa":
            if hash_algorithm == "sha256":
                h = hashes.SHA256()
            elif hash_algorithm == "sha384":
                h = hashes.SHA384()
            elif hash_algorithm == "sha512":
                h = hashes.SHA512()
            else:
                raise ValueError("Unsupported hash algorithm")

            verifier = public_key.verifier(
                signature,
                serialization.BestAvailablePadding(),
                h
            )
            verifier.update(message_bytes)
            verifier.verify()

        elif algorithm == "ecdsa":
            if hash_algorithm == "sha256":
                h = hashes.SHA256()
            elif hash_algorithm == "sha384":
                h = hashes.SHA384()
            elif hash_algorithm == "sha512":
                h = hashes.SHA512()
            else:
                raise ValueError("Unsupported hash algorithm")

            verifier = public_key.verifier(signature, ec.ECDSA(h))
            verifier.update(message_bytes)
            verifier.verify()

        elif algorithm == "ed25519":
            public_key.verify(signature, message_bytes)

        else:
            raise ValueError("Unsupported algorithm")

        logging.info("Signature is valid.")
        return True

    except InvalidSignature:
        logging.error("Signature is invalid.")
        return False
    except Exception as e:
        logging.error(f"Error during verification: {e}")
        return False


def main():
    """
    Main function to handle command-line arguments and perform signing/verification.
    """
    args = setup_argparse()

    if args.action == "sign":
        if not args.private_key:
            logging.error("Private key path is required for signing.")
            sys.exit(1)

        signature = sign_message(args.message, args.private_key, args.algorithm, args.hash_algorithm)

        # Output the signature to stdout (or save to a file if needed)
        print(signature.hex()) #Hex representation of the signature, suitable for storage/transfer


    elif args.action == "verify":
        if not args.public_key or not args.signature:
            logging.error("Public key path and signature path are required for verification.")
            sys.exit(1)

        verify_message(args.message, args.public_key, args.signature, args.algorithm, args.hash_algorithm)


if __name__ == "__main__":
    main()