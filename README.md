Prototype toolkit to generate varied images and derive cryptographic keys.

Features
Multiple entropy sources: CSPRNG, procedural noise, chaotic maps, and randomized transforms.

Rate limiting and retries: token-bucket limiter and exponential backoff.

Deterministic and one-time modes: choose reproducible salts or random salts.

Safety-first docs: threat model, security guidance, and tests included.

Vetted KDFs (Key Derivation Formulas): HKDF by default; examples for Argon2id for low-entropy seeds.



CSPRNG
A Cryptographically Secure Pseudorandom Number Generator (CSPRNG) produces numbers that are unpredictable and suitable for keys, nonces, and salts. It starts from true entropy (seed) and stretches it with algorithms designed so an attacker cannot feasibly predict future outputs or recover past outputs if the internal state is protected. Use OS-provided APIs (e.g., secrets in Python or the kernel RNG) rather than ad‑hoc PRNGs for any security-sensitive work. 

Procedural noise
Procedural noise is a family of mathematical functions (Perlin, Simplex, fractal noise, etc.) that generate continuous, spatially coherent patterns without storing bitmaps. Unlike raw random pixels, procedural noise produces smooth, natural-looking variation (clouds, wood grain, terrain) and can be combined at different scales (octaves) to make complex textures while using little memory. It’s deterministic for a given seed, so it’s useful when you want repeatable but complex patterns.

chaotic maps = simple deterministic formulas that produce unpredictable sequences

Randomized transforms are simple, randomized image operations applied to change pixel layout or appearance: rotations, translations, crops, scaling, shearing, color jitter, blur, palette remapping, and overlays. They are widely used for data augmentation in machine learning and for increasing byte-level variation in generative pipelines. When applied deterministically (fixed seed) they give reproducible variants; when applied with true randomness they increase diversity but break reproducibility. Libraries like torchvision provide standard, well-tested implementations. 

KEY
A cryptographic key is a secret value that must remain confidential because the security of encryption, MACs, or signatures depends on it. Keys are generated with high entropy (CSPRNGs) and sized according to the algorithm (for example, 128/256 bits for symmetric ciphers). If an attacker learns the key, confidentiality and integrity protections fail. Keep keys secret, rotate them when compromised, and store them in secure hardware or vaults when possible.

NONCE
A nonce (number used once) is a value that must be unique for each use with a given key; it is not necessarily secret. Nonces prevent replay attacks and ensure that repeated encryption of the same plaintext produces different ciphertexts in many modes (e.g., AES‑GCM, ChaCha20‑Poly1305). Nonces can be random or sequential; the critical property is no reuse with the same key. Reusing a nonce with the same key in many AEAD modes can catastrophically break confidentiality or integrity. Do not reuse nonces; prefer deterministic counters or large random nonces with collision checks.

SALT
A salt is a non‑secret, unique value mixed into hashing or key‑derivation operations (password hashing, KDFs) to make identical inputs produce different outputs and to defeat precomputed attacks (rainbow tables). Salts are typically generated with a CSPRNG and stored alongside the hash; they do not need to be secret but must be unique per instance. Use a fresh, sufficiently long salt for each password or seed you process.

HASHING
Hashing converts any input into a fixed‑size, one‑way digest; it’s used to verify integrity, fingerprint data, and as a building block for authentication and KDFs. A cryptographic hash function deterministically maps data of any length to a fixed‑length output (the digest). The operation is designed to be fast to compute but computationally infeasible to invert, so you cannot recover the original input from the digest. 





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

