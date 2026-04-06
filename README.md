# Corrupted Oracle

**The standard was compromised. Here's the proof.**

Corrupted Oracle is a browser-based demonstration of three cryptographically secure pseudorandom number generators (CSPRNGs) — including a live, working implementation of the **Dual_EC_DRBG backdoor** that the NSA reportedly planted in a NIST standard.

Generate random numbers from all three algorithms. Run NIST statistical tests. Then watch as the backdoor recovers Dual_EC_DRBG's internal state and predicts every future output — while all statistical tests continue to pass.

**[Live Demo →](https://systemslibrarian.github.io/crypto-lab-iron-letter/)**

---

## What You Can Do

| Feature | Description |
|---------|-------------|
| **HMAC-DRBG** | NIST SP 800-90A §10.1.2 implementation with KAT vector verification |
| **ChaCha20-DRBG** | RFC 8439 ChaCha20-based DRBG (same construction as OpenBSD arc4random) |
| **Dual_EC_DRBG** | SP 800-90A Appendix A.1 with full P-256 elliptic curve arithmetic |
| **Backdoor Attack** | Live state recovery: intercept two output blocks → predict all future output |
| **Statistical Tests** | NIST SP 800-22 subset (Frequency, Block Frequency, Runs, Longest Run) |
| **Bit Heatmap** | Visual comparison — all three look identical. The backdoor is invisible. |

---

## The Math

Dual_EC_DRBG uses two points **P** and **Q** on the P-256 elliptic curve (per SP 800-90A §10.3.1):

1. State update: `s = (s_old · P).x` — multiply old state by P, take x-coordinate
2. Output value: `r = (s · Q).x` — multiply new state by Q
3. Output = `truncate(r)` — drop the high 16 bits (30 bytes from 32)

**The backdoor:** If someone knows the scalar `d = e⁻¹ mod n` such that `Q = e · P`, they can:

1. Observe one output block (30 bytes of `r`, the x-coordinate of the point R = s·Q, missing 16 bits)
2. Try all 2¹⁶ = 65,536 possible completions of the x-coordinate
3. For each candidate point R on the curve, compute **d · R = d · (s·Q) = s · (d·Q) = s · P**
4. `(s · P).x` is the **next internal state** — giving full prediction capability
5. Verify against the second output block; on match, predict every future output

This is a **65,536-candidate brute force** — trivial for any modern processor. Without knowing `d`, computing `d · R` requires solving the elliptic curve discrete log problem — computationally infeasible.

---

## Why Statistical Tests Don't Help

All four NIST SP 800-22 tests pass for Dual_EC_DRBG output — even with the backdoor active:

- **Frequency (Monobit):** Equal 0s and 1s? ✅
- **Block Frequency:** Uniform distribution in blocks? ✅
- **Runs:** Expected number of bit transitions? ✅
- **Longest Run of Ones:** No unexpectedly long runs? ✅

The backdoor is **structural**, not **statistical**. It lives in the algebraic relationship between P and Q, not in any detectable pattern in the output bits. You cannot find it by staring at the output. This is what makes it so dangerous.

---

## Demo vs. Reality

This demonstration uses a **known demo backdoor scalar** — we generate our own `Q = e · P` where we choose `e`. This proves the attack mechanism works mathematically.

We do **not** claim to have recovered the actual scalar relationship between NIST's published P and Q values. The NIST Q point is displayed for reference, but the attack runs against our demo Q.

The real-world implications: whoever chose the NIST Q point — and the NSA is widely believed to have done so — would have known `e` and could have exploited this backdoor against any system using the NIST constants.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Framework | Vite + TypeScript (strict mode) |
| Styling | Tailwind CSS + CSS custom properties |
| Crypto primitives | WebCrypto API (SHA-256/HMAC only) |
| EC arithmetic | Pure TypeScript bigint (no libraries) |
| Deployment | GitHub Pages via Actions |
| Backend | None — entirely client-side |

---

## Local Setup

```bash
git clone https://github.com/systemslibrarian/corrupted-oracle.git
cd corrupted-oracle
npm install
npm run dev
```

Build for production:
```bash
npm run build    # outputs to out/
npm run preview  # preview production build
```

Type-check:
```bash
npx tsc --noEmit
```

---

## Data Sources

- [NIST SP 800-90A Rev 1](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final) — DRBG standard (Dual_EC removed in revision)
- [NIST SP 800-22 Rev 1a](https://csrc.nist.gov/publications/detail/sp/800-22/rev-1a/final) — Statistical test suite
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) — ChaCha20 and Poly1305
- [Bernstein, Lange, Niederhagen — "Dual EC: A Standardized Back Door" (2015)](https://projectbullrun.org/dual-ec/documents/dual-ec-20150731.pdf)
- [Shumow & Ferguson — "On the Possibility of a Back Door in the NIST SP800-90 Dual Ec Prng" (2007)](https://rump2007.cr.yp.to/15-shumow.pdf)
- [Reuters (2013) — "Secret contract tied NSA and security industry pioneer"](https://www.reuters.com/article/us-usa-security-rsa-idUSBRE9BJ1C220131220/)

---

*So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31*
