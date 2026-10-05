# Qryptive – PQC Algorithm Detection Test Repo

Test data for checking that Qryptive reports post-quantum algorithms
(ML-KEM / Kyber, ML-DSA / Dilithium, Falcon, SPHINCS+ / SLH-DSA) as **PQC safe**
and **never** as RSA, DSA or ECC vulnerable.

## Layout

| Folder | Library | Test cases | Expected |
|---|---|---|---|
| `python/oqs_python/` | oqs-python (liboqs wrapper) | TC-01 to TC-04 | PQC safe |
| `python/pqcrypto_lib/` | pqcrypto | TC-05 to TC-09 | PQC safe |
| `c/liboqs/` | liboqs (C) | TC-10 to TC-13 | PQC safe |
| `go/circl/` | Cloudflare circl | TC-14 to TC-17 | PQC safe |
| `java/bouncycastle/` | BouncyCastle | TC-18 to TC-22 | PQC safe |
| `edge_cases/` | misleading names, hybrid, TLS config | TC-23 to TC-25 | see file header |
| `controls/` | RSA, ECDSA, DSA | TC-26 to TC-28 | **must be flagged** |

The TC number is written at the top of every file, so you can match a Qryptive
finding to its test case quickly.

## Notes
- Circl has no Falcon implementation, so Falcon is covered by the other 4 libraries.
- `*_legacy*` files use the old names (Kyber, Dilithium) on purpose.
- Every ML-DSA / SLH-DSA file is also a trap for plain text matching on "DSA".
- The code follows each library's documented API. Qryptive scans source code, so the
  files do not need to be built or run for the test.

## How to use
1. Push this folder to a new Git repo (GitHub / GitLab / Bitbucket — whatever Qryptive connects to).
2. Connect / upload the repo in Qryptive and run a code scan.
3. Fill the **Actual Output** column in `Qryptive_PQC_Detection_TestCases.xlsx`.
