# api/server.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Tuple
import uvicorn
from frost import Participant, Aggregator, Point, G, Q
from base64 import b64encode, b64decode
import hashlib

app = FastAPI(title="FROST API", description="API for FROST threshold signatures")

# Store participants in memory (in production, use proper storage)
participants = {}
group_keys = {}

class ParticipantSetup(BaseModel):
    threshold: int
    total_participants: int

class SignRequest(BaseModel):
    message: str
    participant_indexes: List[int]

def bip340_hash_message(message: str) -> bytes:
    """Hash a message according to BIP340 specification"""
    tag_hash = hashlib.sha256(b"BIP0340/aux").digest()
    tag_hash2 = hashlib.sha256(b"BIP0340/nonce").digest()
    tag_hash3 = hashlib.sha256(b"BIP0340/challenge").digest()
    # First hash with aux tag
    h = hashlib.sha256(tag_hash + tag_hash + message.encode()).digest()
    # Then hash with nonce tag
    h = hashlib.sha256(tag_hash2 + tag_hash2 + h).digest()
    # Finally hash with challenge tag
    return hashlib.sha256(tag_hash3 + tag_hash3 + h).digest()

def verify_schnorr_signature(public_key: Point, message: bytes, signature_hex: str) -> bool:
    """Verify a Schnorr signature according to BIP340"""
    try:
        print("\n=== SCHNORR VERIFICATION DEBUG ===")
        print(f"Input signature (hex): {signature_hex}")
        print(f"Input public key (x): {public_key.xonly_serialize().hex()}")
        print(f"Input message: {message}")
        
        # Parse signature
        sig_bytes = bytes.fromhex(signature_hex)
        if len(sig_bytes) != 64:
            print(f"Invalid signature length: {len(sig_bytes)} bytes (expected 64)")
            return False
            
        # Split into R and s components
        R_bytes = sig_bytes[:32]
        s_bytes = sig_bytes[32:]
        
        # Convert to integers
        s = int.from_bytes(s_bytes, "big")
        print(f"\nSignature components:")
        print(f"R (hex): {R_bytes.hex()}")
        print(f"s (hex): {s_bytes.hex()}")
        print(f"s (int): {s}")
        
        # Validate s is in range
        if s >= Q:
            print(f"s is out of range: {s} >= {Q}")
            return False
            
        # Reconstruct R point (will have even y by construction)
        R = Point.xonly_deserialize(R_bytes.hex())
        print(f"\nReconstructed R point:")
        print(f"R.x: {R.x}")
        print(f"R.y: {R.y}")
        
        # Get challenge hash
        e = Aggregator.challenge_hash(R, public_key, message)
        print(f"\nChallenge hash:")
        print(f"e: {e}")
        
        # Verify R = s*G - e*P
        sG = s * G
        print(f"\nsG point:")
        print(f"sG.x: {sG.x}")
        print(f"sG.y: {sG.y}")
        
        eP = e * public_key
        print(f"\neP point:")
        print(f"eP.x: {eP.x}")
        print(f"eP.y: {eP.y}")
        
        R_calc = sG + (-eP)
        print(f"\nCalculated R point:")
        print(f"R_calc.x: {R_calc.x}")
        print(f"R_calc.y: {R_calc.y}")
        
        # Check x-coordinates match
        matches = R.x == R_calc.x
        print(f"\nVerification result:")
        print(f"R.x == R_calc.x: {matches}")
        print(f"R.x: {R.x}")
        print(f"R_calc.x: {R_calc.x}")
        
        return matches

    except Exception as e:
        print(f"\nSignature verification error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False

@app.post("/setup")
async def setup_participants(setup: ParticipantSetup):
    """Initialize a new set of participants"""
    try:
        # Create participants
        participants.clear()  # Reset for demo purposes
        for i in range(1, setup.total_participants + 1):
            participants[i] = Participant(
                index=i,
                threshold=setup.threshold,
                participants=setup.total_participants
            )
        
        # Initialize key generation
        for p in participants.values():
            p.init_keygen()
            p.generate_shares()
        
        # Exchange and aggregate shares
        for p in participants.values():
            other_shares = []
            for other_p in participants.values():
                if other_p.index != p.index:
                    other_shares.append(other_p.shares[p.index - 1])
            p.aggregate_shares(tuple(other_shares))
        
        # Derive public key for all participants
        for i, p in participants.items():
            other_commitments = tuple(
                participants[j].coefficient_commitments[0]
                for j in participants if j != i
            )
            p.derive_public_key(other_commitments)
        group_keys['public_key'] = participants[1].public_key
        
        # Return public key in both hex and base64
        xonly_bytes = participants[1].public_key.xonly_serialize()
        # Derive Taproot address for testnet using local function
        taproot_addr = taproot_address(xonly_bytes, testnet=True)
        return {
            "status": "success",
            "public_key_hex": xonly_bytes.hex(),
            "public_key_b64": b64encode(xonly_bytes).decode(),
            "taproot_address_testnet": taproot_addr
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/sign")
async def sign_message(request: SignRequest):
    """Sign a message using threshold signatures"""
    try:
        if not participants or 'public_key' not in group_keys:
            raise HTTPException(status_code=400, detail="Participants not initialized")
        
        print("\n=== SIGNATURE GENERATION DEBUG ===")
        print(f"Message: {request.message}")
        print(f"Message bytes: {request.message.encode().hex()}")
        print(f"Public key: {group_keys['public_key'].xonly_serialize().hex()}")
        print(f"Participant indexes: {request.participant_indexes}")
        
        # Convert message to bytes
        message = request.message.encode()
        
        # Generate nonces for signing participants
        signing_participants = [participants[i] for i in request.participant_indexes]
        for p in signing_participants:
            p.generate_nonce_pair()
            print(f"\nParticipant {p.index} nonce pair:")
            print(f"First nonce: {p.nonce_pair[0]}")
            print(f"Second nonce: {p.nonce_pair[1]}")
            print(f"First commitment: ({p.nonce_commitment_pair[0].x}, {p.nonce_commitment_pair[0].y})")
            print(f"Second commitment: ({p.nonce_commitment_pair[1].x}, {p.nonce_commitment_pair[1].y})")
        
        # Create aggregator
        nonce_pairs = tuple(p.nonce_commitment_pair for p in signing_participants)
        aggregator = Aggregator(
            group_keys['public_key'],
            message,
            nonce_pairs,
            tuple(request.participant_indexes)
        )
        
        # Get signing inputs
        message, nonce_commitment_pairs = aggregator.signing_inputs()
        
        # Generate partial signatures
        signature_shares = []
        for p in signing_participants:
            share = p.sign(message, nonce_commitment_pairs, tuple(request.participant_indexes))
            print(f"\nParticipant {p.index} signature share: {share}")
            signature_shares.append(share)
        
        # Get final signature
        final_signature = aggregator.signature(tuple(signature_shares))
        print(f"\nFinal signature: {final_signature}")
        
        # Verify the signature before returning
        if not verify_schnorr_signature(group_keys['public_key'], message, final_signature):
            raise HTTPException(
                status_code=500, 
                detail="Generated signature failed verification"
            )
        
        return {
            "status": "success",
            "signature": final_signature,
            "public_key": group_keys['public_key'].xonly_serialize().hex(),
            "message": request.message
        }
    except Exception as e:
        print(f"\nError during signature generation: {str(e)}")
        import traceback
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

# Bech32m encoding functions (from BIP-350)
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def taproot_address(xonly_bytes, testnet=True):
    hrp = 'tb' if testnet else 'bc'
    data = [1] + convertbits(list(xonly_bytes), 8, 5)
    return bech32_encode(hrp, data)

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)