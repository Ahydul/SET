import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# Here to make it easier. Only bank has access to the private key
bank_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
bank_public_key = bank_private_key.public_key()

def _rsa_verify(pub, sig, msg):
    try:
        pub.verify(
            sig, 
            msg, 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
            ), 
            hashes.SHA256()
        )
        return True
    except: return False

def _rsa_sign(pri, msg):
    return pri.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), 
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def _rsa_encrypt(pub, msg):
    return pub.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def _rsa_decrypt(pri, msg):
    return pri.decrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def _sha_hash(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def verify_merchant(received_OI, received_PIMD, dual_signature, pub_key) -> bool:
    reconstructed_POMD = _sha_hash(received_PIMD + _sha_hash(received_OI))
    return _rsa_verify(pub_key, dual_signature, reconstructed_POMD)

def verify_bank(dual_envelope, pub_key):
    try:
        decrypted_payload = _rsa_decrypt(bank_private_key, dual_envelope)
        parts = decrypted_payload.split(b"||")
        recovered_PI = parts[0]
        recovered_OIMD = parts[1]
        recovered_signature = parts[2]
        
        reconstructed_POMD = _sha_hash(_sha_hash(recovered_PI) + recovered_OIMD)
        return _rsa_verify(pub_key, recovered_signature, reconstructed_POMD)
    except Exception as e:
        return false

def purchase_request(received_OI, received_PIMD, dual_signature, pub_key, dual_envelope):
    print("Purchase request, received OI, PIMD, dual_signature, customer_public_key and dual_envelope")
    result = verify_merchant(received_OI, received_PIMD, dual_signature, pub_key)
    if result:
        print("Merchant-side verification successful. Verifying with bank...")
        result2 = verify_bank(dual_envelope, pub_key)
        if result2:
            print("Bank-side verification successful.")
        else:
            print("Bank-side verification failed.")
    else:
        print("Merchant-side verification failed.")


def main():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    PI = b"Pay 100 DKK to MerchantX"
    OI = b"Order #2456: 2 items total 100 DKK"

    PIMD = _sha_hash(PI)
    OIMD = _sha_hash(OI)
    POMD = _sha_hash(PIMD + OIMD) #bytes + bytes is concatenation
    dual_signature = _rsa_sign(private_key, POMD)

    dual_envelope = _rsa_encrypt(bank_public_key, PI + b"||" + OIMD + b"||" + dual_signature)

    print("PI:", PI)
    print("OI:", OI)
    print("PIMD:", PIMD)
    print("OIMD:", OIMD)
    print("POMD:", POMD)
    print("dual_signature:", dual_signature)

    purchase_request(OI, PIMD, dual_signature, public_key, dual_envelope)

if __name__ == "__main__":
    main()