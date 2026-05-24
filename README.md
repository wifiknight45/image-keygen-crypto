Prototype toolkit to generate varied images and derive cryptographic keys.

Features
Multiple entropy sources: CSPRNG, procedural noise, chaotic maps, and randomized transforms.

Vetted KDFs: HKDF by default; examples for Argon2id for low-entropy seeds.

Rate limiting and retries: token-bucket limiter and exponential backoff.

Deterministic and one-time modes: choose reproducible salts or random salts.

Safety-first docs: threat model, security guidance, and tests included.

Installation

git clone https://github.com/wifiknight45/image-keygen-crypto.git
cd image-keygen-crypto

python -m venv .venv

source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

Usage
Generate a single non-reproducible key
python -m src.image_keygen.generate_one
output: prints the derived key hex and the random salt used. Save the salt if you need to decrypt or reproduce.

This script makes noisy pictures, turns each picture into a fixed string of bytes, and then uses a standard 
cryptographic tool (a KDF) to turn those bytes into a secret key. It mixes several random sources, limits 
how fast it runs, and handles errors so it’s safer to experiment with—but it’s still a prototype, not a drop-in
production key generator.


How it works:

1. Make a messy image; the program fills an image with lots of different kinds of randomness (true random bytes 
from the OS, procedural noise, chaotic sequences) so the image looks like static.

2. Turn the picture into bytes, then the image is saved as a PNG and those file bytes are the raw material.

3. Derive a key - those bytes are fed into a Key Derivation Function (KDF) like HKDF or Argon2 to produce a fixed-length cryptographic key. `


PNG bytes are deterministic: Saving the image in a controlled way gives a repeatable byte string for the 
same image; but encoder options and metadata can change the bytes, so the script fixes those options. 
Deterministic serialization is required if you want reproducible keys. 

KDFs make keys safe: A KDF like HKDF first extracts randomness and then expands it into one or more keys. This prevents 
simple hashing mistakes and gives you independent keys for different uses. HKDF is a standard used in many secure protocols.

Reproducible vs non-reproducible keys
Non-reproducible (default): salt is random each run; you cannot recreate the same key later unless you store the salt. This is safer for one-time keys.

Reproducible (opt-in): salt and image generation must be deterministic and protected like a password. In this case treat the seed and salt as secrets. 

