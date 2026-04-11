# Corrupted Oracle

**The standard was compromised. Here's the proof.**

---

## What It Is

Corrupted Oracle is a browser-based demonstration of three deterministic random bit generators (DRBGs): **HMAC-DRBG** (NIST SP 800-90A §10.1.2), **ChaCha20-DRBG** (RFC 8439-based), and **Dual\_EC\_DRBG** (SP 800-90A Appendix A.1) — including a live implementation of the Dual\_EC\_DRBG backdoor using P-256 elliptic curve arithmetic. It shows that a structurally backdoored CSPRNG can pass all standard statistical randomness tests while an attacker with knowledge of the secret relationship between the curve points P and Q can recover internal state and predict all future output. The security model is symmetric-key DRBG construction, with the backdoor exploiting an asymmetric (elliptic curve) trapdoor embedded in the generator constants.

## When to Use It

- **Teaching the Dual\_EC\_DRBG backdoor** — the demo runs real EC math in the browser so students can see state recovery happen live, not just read about it.
- **Demonstrating why statistical tests are insufficient** — all four NIST SP 800-22 tests (Frequency, Block Frequency, Runs, Longest Run) pass on backdoored output, proving that passing tests does not mean a generator is safe.
- **Comparing DRBG constructions side by side** — HMAC-DRBG, ChaCha20-DRBG, and Dual\_EC\_DRBG generate output in parallel so you can see identical statistical profiles with fundamentally different security properties.
- **Illustrating supply-chain trust in cryptographic standards** — the demo makes concrete what it means for a standards body to publish compromised constants.
- **Do not use any code from this project in production** — the Dual\_EC\_DRBG implementation is intentionally backdoored for educational purposes and the demo DRBGs are not hardened for real-world use.

## Live Demo

**[Live Demo →](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/)**

Generate random output from all three DRBGs, run NIST SP 800-22 statistical tests against each, and trigger the Dual\_EC\_DRBG backdoor attack to watch the attacker brute-force 2¹⁶ candidates and recover internal state. You can reseed any generator and view bit heatmaps comparing output from all three algorithms.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-corrupted-oracle.git
cd crypto-lab-corrupted-oracle
npm install
npm run dev
```

## Part of the Crypto-Lab Suite

This project is one module in the Crypto-Lab collection — see all demos at [systemslibrarian.github.io/crypto-lab/](https://systemslibrarian.github.io/crypto-lab/).

---

*So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31*
