# TRUST-DISTRUSTED-ROOT-001: Certificate chain anchored on a root removed from browser trust stores

CryptoScan reports this finding, at HIGH, for a PEM certificate in the scanned files when:

1. the certificate is emSign ECC Root CA - G3: its public key is the root's key listed below (rule 3), or
2. the certificate's signature verifies under that root's key (rule 4): the certificate chains to the root, whether or not the root is in the file.

After the eMudhra intermediate key compromise, reported in Mozilla Bug 2083449 on 2026-10-17, Mozilla removed this root in an emergency change, and Chrome's removal of the root for all devices is dated 2026-10-27. Chains that end at this root stop validating in browsers that no longer trust it. This is a trust change, not a quantum risk, so the finding does not count toward the quantum migration readiness score, the QRAMM levels or the CBOM components.

The match is made on the key, never on a name. CryptoScan decodes each certificate block and compares the SHA-256 of its DER SubjectPublicKeyInfo (its SPKI hash) with the root's, then checks its signature against the root's key.

`cryptoscan gate .` exits 1 on this finding. `cryptoscan scan .` fails only on CRITICAL findings by default; `cryptoscan scan . --fail-on high` exits 1 on it. `cryptoscan gate . --ignore TRUST-DISTRUSTED-ROOT-001` leaves it out; the certificate ignore examples in the help, `cryptoscan gate . --ignore "CERT-*" --ignore-category Certificate`, do not.

## Fields

| Field | Value |
|-------|-------|
| `matchedValue` | Rule 3: the certificate's SPKI hash. Rule 4: the SHA-256 of the certificate itself. |
| `valueType` | `spkiSha256` (rule 3) or `certSha256` (rule 4) |
| `issuerSpkiSha256` | Rule 4 only: the SPKI hash of the root's key, which the signature verifies under |
| `keyUse` | `root` |
| `rule` | `3` or `4` |
| `kind` | `distrustedRoot` |
| `distrustDate` | `2026-10-27` |

Values are lowercase hex without colons. The JSON report carries them in the finding's `metadata`, SARIF in the result's `properties`, and the text report on its `SPKI SHA-256:`, `Certificate SHA-256:` and `Signed by:` rows.

## Listed root

The root is listed by its SPKI hash and by the SHA-256 of its certificate, in hex and in base64. The certificate is in [`pkg/patterns/testdata/trust/root`](../../pkg/patterns/testdata/trust/root), named by its SHA-256.

<!-- trust-key-table:start (written by go generate ./pkg/patterns) -->

| Key | Use | Value | SHA-256 (hex) | SHA-256 (base64) |
|-----|-----|-------|---------------|------------------|
| emSign ECC Root CA - G3 | root | SPKI | `8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782` | `jUF9st2L9eMITR4/GW1YOEnYG91MAMcLnTk2npa4x4I=` |
| emSign ECC Root CA - G3 | root | Certificate | `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b` | `hqHsugicSo07vic0xhK6NB2BPgQ8+eioYs1cV6Nrvms=` |

<!-- trust-key-table:end -->

## Dates

- 2026-10-17: the eMudhra intermediate key compromise is reported in Mozilla Bug 2083449, listed as [TRUST-COMPROMISED-KEY-001](trust-compromised-key.md).
- 2026-10-18: eMudhra revokes the eight intermediates.
- 2026-10-27: Chrome's removal of emSign ECC Root CA - G3 for all devices.

## Verify

The finding's `Verify:` line recomputes its matched value from the scanned file with openssl and POSIX tools only, and makes no network request. It prints the bare lowercase hex value, the same under OpenSSL and LibreSSL. In the commands below, `FILE` is the file the finding names and `LINE` is the line of its `-----BEGIN CERTIFICATE-----` header.

```sh
# Rule 3: print the certificate's SPKI hash
awk "NR>=$LINE" "$FILE" | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n'
```

```sh
# Rule 4: print the certificate's SHA-256
awk "NR>=$LINE" "$FILE" | openssl x509 -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n'
```

For rule 4, confirm the signature against the root. `ROOT` is the root's certificate file from the directory above. This needs OpenSSL: the `verify` command of LibreSSL has neither option.

```sh
# Rule 4: confirm that the root's key signed the certificate (OpenSSL)
awk "NR>=$LINE" "$FILE" | openssl x509 -out flagged.pem
openssl verify -no_check_time -partial_chain -trusted "$ROOT" flagged.pem
```

It prints `flagged.pem: OK` when the root's key signed the certificate, or when the certificate is the root.

## Check a deployed server

The scan reads only the files in the scanned tree. It makes no network request, does not read the system trust store, and does not read Markdown (`.md`) or text (`.txt`) files. By default it also leaves out directories such as `testdata`, `fixtures` and `examples`; `cryptoscan scan . --include-skipped` reads them. To check the chain a server presents, save each certificate it sends and print its SPKI hash. `SERVER` is the server's host and port, such as `example.org:443`, and `NAME` is the name the server answers to, such as `example.org`. OpenSSL takes an IPv6 address in brackets, as `[2001:db8::1]:443`, and LibreSSL without them, as `2001:db8::1:443`.

```sh
# Save the certificates the server sends and print the SPKI hash of each
openssl s_client -connect "$SERVER" -servername "$NAME" -showcerts </dev/null 2>/dev/null |
  awk '/-----BEGIN CERTIFICATE-----/{n++; inside=1} inside{print > ("served-" n ".pem")} /-----END CERTIFICATE-----/{inside=0; close("served-" n ".pem")}'
for f in served-*.pem; do
  [ -f "$f" ] || { echo "no certificate received from $SERVER" >&2; break; }
  printf '%s ' "$f"
  openssl x509 -in "$f" -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n'
  echo
done
```

The root's SPKI hash in that list means the server sends the root itself. A server usually sends the chain without its root, so check whether the last certificate it sends is signed by the root:

```sh
# Check the last certificate the server sends against the root (OpenSSL)
n=$(ls served-*.pem | wc -l | tr -d ' ')
openssl verify -no_check_time -partial_chain -trusted "$ROOT" "served-$n.pem"
```

It prints `served-N.pem: OK`, with the number of that certificate, when the chain ends at this root.

## Fix

- Removed root (`keyUse` `root`): Move the chain to a CA whose root stays trusted, and remove emSign ECC Root CA - G3 from any bundle you ship; Chrome removes it for all devices on 2026-10-27.

## Sources

- Mozilla Bug 2083449: <https://bugzilla.mozilla.org/show_bug.cgi?id=2083449>
- Google's post on Chrome and Android: <https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/>
