# crypto-lab-corrupted-oracle

## What It Is

Corrupted Oracle is a browser-based demonstration of three deterministic random bit generators (DRBGs): **HMAC-DRBG** (NIST SP 800-90A §10.1.2), **ChaCha20-DRBG** (RFC 8439-based), and **Dual\_EC\_DRBG** (SP 800-90A Appendix A.1) — including a live implementation of the Dual\_EC\_DRBG backdoor using P-256 elliptic curve arithmetic. It shows that a structurally backdoored CSPRNG can pass all standard statistical randomness tests while an attacker with knowledge of the secret relationship between the curve points P and Q can recover internal state and predict all future output. The security model is symmetric-key DRBG construction, with the backdoor exploiting an asymmetric (elliptic curve) trapdoor embedded in the generator constants.

## When to Use It

- **Teaching the Dual\_EC\_DRBG backdoor** — the demo runs real EC math in the browser so students can see state recovery happen live, not just read about it.
- **Demonstrating why statistical tests are insufficient** — all four NIST SP 800-22 tests (Frequency, Block Frequency, Runs, Longest Run) pass on backdoored output, proving that passing tests does not mean a generator is safe.
- **Comparing DRBG constructions side by side** — HMAC-DRBG, ChaCha20-DRBG, and Dual\_EC\_DRBG generate output in parallel so you can see identical statistical profiles with fundamentally different security properties.
- **Illustrating supply-chain trust in cryptographic standards** — the demo makes concrete what it means for a standards body to publish compromised constants.
- **Do not use any code from this project in production** — the Dual\_EC\_DRBG implementation is intentionally backdoored for educational purposes and the demo DRBGs are not hardened for real-world use.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-corrupted-oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/)**

Generate random output from all three DRBGs, run NIST SP 800-22 statistical tests against each, and trigger the Dual\_EC\_DRBG backdoor attack to watch the attacker brute-force 2¹⁶ candidates and recover internal state. You can reseed any generator and view bit heatmaps comparing output from all three algorithms.

## What Can Go Wrong

- Trusting a CSPRNG because it passes statistical randomness tests: Dual\_EC\_DRBG passes the NIST SP 800-22 battery yet is fully predictable to anyone who knows the secret relationship between P and Q.
- Adopting unverifiable "magic constants": when generator constants cannot be independently re-derived, a standards body or vendor can embed a trapdoor that users can never detect from the output alone.
- DRBG state compromise without reseeding: an attacker who recovers internal state can predict all future output until the generator is reseeded with fresh entropy.
- Insufficient entropy at seed time: a DRBG is only as strong as its seed, so low-entropy or predictable seeding makes the output guessable regardless of the algorithm.
- Output-truncation assumptions: Dual\_EC's relatively small truncation left enough bits in each block to make state recovery cheap for the trapdoor holder.

## Real-World Usage

- HMAC-DRBG, Hash-DRBG, and CTR-DRBG (NIST SP 800-90A) are the standard DRBGs used in TLS libraries, operating-system RNGs, and FIPS-validated cryptographic modules.
- ChaCha20-based generators back the Linux `getrandom()` / `/dev/urandom` CSPRNG, BSD `arc4random`, and the RNGs of many language runtimes.
- Dual\_EC\_DRBG was a published NIST standard that shipped in products such as RSA BSAFE and Juniper ScreenOS before being withdrawn over the backdoor concerns this demo reconstructs — a real cautionary tale in standards trust.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-corrupted-oracle
cd crypto-lab-corrupted-oracle
npm install
npm run dev
```

## Related Demos
- [crypto-lab-drbg-arena](https://systemslibrarian.github.io/crypto-lab-drbg-arena/) — HMAC_DRBG, CTR_DRBG, and Hash_DRBG (NIST SP 800-90A) compared head to head.
- [crypto-lab-vrf-gate](https://systemslibrarian.github.io/crypto-lab-vrf-gate/) — verifiable random functions and VDFs, randomness you can prove rather than trust.
- [crypto-lab-phantom-vault](https://systemslibrarian.github.io/crypto-lab-phantom-vault/) — HMAC-DRBG with rejection sampling in an applied key-derivation setting.
- [crypto-lab-chacha20-stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — the ChaCha20 keystream that the ChaCha20-DRBG in this demo is built on.

## Verifying the Cryptography

Don't take the demo's word for it — the math is checked by an automated test suite:

```bash
npm test
```

The suite verifies, against authoritative sources:

- **HMAC-DRBG** reproduces every NIST CAVS 14.3 `HMAC_DRBG(SHA-256)` known-answer vector.
- **ChaCha20** reproduces the RFC 8439 §2.3.2 keystream test vector.
- **P-256** arithmetic is correct: the generator has the right order (`n·G = ∞`), and both the standard generator P and the published constant Q lie on the curve.
- **The trapdoor holds**: `d·Q = P`, where `d = e⁻¹ mod n` and `Q = e·P` — this is the relationship that turns intercepted output back into internal state.
- **The end-to-end attack** recovers the generator's state from two output blocks and predicts its future output exactly.

A note on speed: the backdoor search is genuinely cheap — in optimized native code it finishes in well under a second. This project runs the same elliptic-curve math from scratch in the browser with plain `BigInt` (written for clarity, not speed), so the live attack takes tens of seconds and you can watch every candidate fall in real time. The cost to an attacker who holds the secret is trivial either way.

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
