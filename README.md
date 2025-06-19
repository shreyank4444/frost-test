# FROST

BIP340 compatible implementation of Flexible Round-Optimized Schnorr Threshold Signatures (FROST).

This work is made possible with the support of Brink.

* [Brink blog: Jesse Posner on FROST](https://brink.dev/blog/2021/04/15/frost/)
* [Introductory slides](FROST.pdf)
* [FROST flow diagram](dot/api/frost.pdf)

## Requirements
python 3.10.2+

## Usage

### Standalone Demo
Run the basic FROST demo with 5 participants and 3-of-5 threshold:

```bash
python3 server.py
```

This will:
1. Create 5 participants 
2. Generate and exchange key shares
3. Create a threshold signature using the first 3 participants
4. Verify the signature

### API Server
Start the FastAPI server for interactive testing:

```bash
# Activate virtual environment
source venv/bin/activate

# Start the API server
python3 -m uvicorn api.server:app --host 0.0.0.0 --port 8000
```

#### API Endpoints

**Setup participants:**
```bash
curl -X POST "http://localhost:8000/setup" \
  -H "Content-Type: application/json" \
  -d '{"threshold": 3, "total_participants": 5}'
```

**Sign a message:**
```bash
# Sign with participants 1, 2, 3
curl -X POST "http://localhost:8000/sign" \
  -H "Content-Type: application/json" \
  -d '{"message": "test message", "participant_indexes": [1, 2, 3]}'

# Sign with participants 3, 4, 5
curl -X POST "http://localhost:8000/sign" \
  -H "Content-Type: application/json" \
  -d '{"message": "test message", "participant_indexes": [3, 4, 5]}'
```

The API supports any combination of participants as long as the threshold is met (3 out of 5 in this example).

### Running the tests
see: [tests/README.md](tests/README.md)
