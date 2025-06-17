import secrets
from src.frost import Participant, Aggregator, G, Q, Point

# --- FROST Network Setup ---
N = 3  # Number of participants
T = 2  # Threshold

# 1. Create participants
participants = [Participant(index=i+1, threshold=T, participants=N) for i in range(N)]

# 2. Each participant runs keygen
for p in participants:
    p.init_keygen()

# 3. Each participant generates shares
for p in participants:
    p.generate_shares()

# 4. Each participant aggregates shares from others
for p in participants:
    others_shares = tuple(
        other.shares[p.index - 1] for other in participants if other != p
    )
    p.aggregate_shares(others_shares)

# 5. Each participant derives the group public key
for p in participants:
    other_commitments = tuple(
        other.coefficient_commitments[0] for other in participants if other != p
    )
    p.derive_public_key(other_commitments)

# All participants should have the same group public key
pubkeys = [p.public_key for p in participants]
assert all(pk == pubkeys[0] for pk in pubkeys), "Public keys do not match!"
group_pk = pubkeys[0]
print(f"\nGroup Public Key (x, y):\n{group_pk}")

# --- Signing a message ---
msg = b"Hello from FROST!"

# 6. Each participant generates a nonce pair
for p in participants:
    p.generate_nonce_pair()

# 7. Choose a signing subset (threshold T)
signing_participants = participants[:T]  # e.g., first two
signing_indexes = tuple(p.index for p in signing_participants)
nonce_commitment_pairs = tuple(p.nonce_commitment_pair for p in signing_participants)

# 8. Aggregator prepares signing inputs
agg = Aggregator(
    group_pk,
    msg,
    nonce_commitment_pairs,
    signing_indexes,
)
message, nonce_commitments = agg.signing_inputs()

# 9. Each signing participant produces their signature share
sig_shares = tuple(
    p.sign(message, nonce_commitments, signing_indexes) for p in signing_participants
)

# 10. Aggregator combines signature shares into a final signature
signature = agg.signature(sig_shares)
print(f"\nSignature (hex): {signature}")

# 11. Verify the signature (manual check, as in the tests)
sig_bytes = bytes.fromhex(signature)
R = Point.xonly_deserialize(sig_bytes[0:32].hex())
z = int.from_bytes(sig_bytes[32:64], "big")

challenge_hash = Aggregator.challenge_hash(R, group_pk, msg)
# Negate Y if Y.y is odd
pk = group_pk
if pk.y % 2 != 0:
    pk = -pk

# R ≟ g^z * Y^-c
left = R
right = (z * G) + (Q - challenge_hash) * pk
print(f"\nSignature verification: {left == right}")
if left == right:
    print("Signature is valid!")
else:
    print("Signature is INVALID!")

# --- End of demo --- 