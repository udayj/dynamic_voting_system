# based on https://www.cairo-lang.org/docs/hello_cairo/voting.html
import json

from starkware.crypto.signature.signature import (
    pedersen_hash, private_to_stark_key, sign)

# Set an identifier that will represent what we're voting for.
# This will appear in the user's signature to distinguish
# between different polls.
POLL_ID = 10018

# Generate key pairs.
priv_keys = []
pub_keys = []
prev_state = []
for i in range(10):
    priv_key = 123456 * i + 654321 
    priv_keys.append(priv_key)

    pub_key = private_to_stark_key(priv_key)
    pub_keys.append(pub_key)
    prev_state.append(0)
# Generate 3 votes of voters 3, 5, 6, and 8 (3 & 8 toggle their votes, 5 is same and 6 is new)
votes = []
for (voter_id, vote) in [(3, 2), (5, 2),  (6,1), (8, 2)]:
    r, s = sign(
        msg_hash=pedersen_hash(POLL_ID, vote),
        priv_key=priv_keys[voter_id])
    votes.append({
        'voter_id': voter_id,
        'vote': vote,
        'r': hex(r),
        's': hex(s),
    })

# Write the data (public keys and votes) to a JSON file.
prev_state[3]=1
prev_state[5]=2
prev_state[8]=1
input_data = {
    'public_keys': list(map(hex, pub_keys)),
    'votes': votes,
    'prev_state':prev_state
}

with open('voting_input2.json', 'w') as f:
    json.dump(input_data, f, indent=4)
    f.write('\n')