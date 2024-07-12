import cbor2
from cose.messages import Sign1Message
from cose.keys import CoseKey
from cose.keys.keyparam import KpKty, KpAlg
from cose.keys.curves import Ed25519
from cose.algorithms import EdDSA
from cose.headers import Algorithm
from cose.keys.keyparam import EC2KpCurve, EC2KpX, EC2KpY
from hashlib import blake2b
import base64

# Function to create a Sign1Message from CBOR with a payload
def cose_sign1_from_cbor_with_payload(cbor_data, payload):
    decoded = cbor2.loads(bytes.fromhex(cbor_data))

    if not isinstance(decoded, list) or len(decoded) != 4:
        raise ValueError('Invalid COSE_SIGN1')

    protected_map = cbor2.loads(decoded[0])
    unprotected_map = decoded[1]
    signature = decoded[3]

    sign1_msg = Sign1Message(phdr=protected_map, uhdr=unprotected_map, payload=payload, signature=signature)
    return sign1_msg

# Function to decode and verify a COSE Sign1 message
def get_signature_content(sign, message):
    sign1_msg = Sign1Message.decode(bytes.fromhex(sign))
    
    print(f"decoded Signature: {sign1_msg}")
    print(f"protected map: {sign1_msg.phdr}")

    payload = sign1_msg.payload
    unprotected_map = sign1_msg.uhdr
    is_hashed = unprotected_map.get('hashed', False)

    if not payload or payload == b'':
        if is_hashed:
            message_hash = blake2b(message.encode(), digest_size=28).digest()
            sign1_msg.payload = message_hash
        else:
            sign1_msg.payload = message.encode()

    print(sign1_msg)
    return sign1_msg

# Example usage
cbor_data = "YOUR_CBOR_DATA_HEX"
payload = b"YOUR_PAYLOAD"

try:
    sign1_msg = cose_sign1_from_cbor_with_payload(cbor_data, payload)
    print(f"Sign1Message: {sign1_msg}")
except Exception as e:
    print(f"Error: {e}")

# Example to verify
signature_hex = "YOUR_SIGNATURE_HEX"
message = "YOUR_MESSAGE"

try:
    sign1_msg = get_signature_content(signature_hex, message)
    print(f"Verified Sign1Message: {sign1_msg}")
except Exception as e:
    print(f"Error: {e}")
