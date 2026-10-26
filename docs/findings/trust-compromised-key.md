# TRUST-COMPROMISED-KEY-001: Certificate with a publicly compromised CA key

CryptoScan reports this finding, at CRITICAL, for a PEM certificate in the scanned files when:

1. the certificate's public key is one of the eight eMudhra intermediate CA keys listed below (rule 1), or
2. the certificate's signature verifies under one of those keys (rule 2): an intermediate with a listed key issued it, whether or not that intermediate's certificate is in the file.

The private keys of the eight intermediates were recovered by independent parties and reported in Mozilla Bug 2083449 on 2026-10-17. eMudhra revoked the eight on 2026-10-18 and the browser root programs block the keys. A bundle that still trusts one of these keys accepts certificates anyone can mint, and a chain through one of them no longer validates.

The match is made on the key, never on a name. CryptoScan decodes each certificate block and compares the SHA-256 of its DER SubjectPublicKeyInfo (its SPKI hash) with the listed keys, then checks its signature against each listed key. The key is compromised already, without a quantum computer, so the finding does not count toward the quantum migration readiness score, the QRAMM levels or the CBOM components.

`cryptoscan scan .` and `cryptoscan gate .` both exit 1 on this finding. `cryptoscan scan . --ignore TRUST-COMPROMISED-KEY-001` leaves it out; the certificate ignore examples in the help, `cryptoscan scan . --ignore "CERT-*" --ignore-category Certificate`, do not.

## Fields

| Field | Value |
|-------|-------|
| `matchedValue` | Rule 1: the certificate's SPKI hash. Rule 2: the SHA-256 of the certificate itself. |
| `valueType` | `spkiSha256` (rule 1) or `certSha256` (rule 2) |
| `issuerSpkiSha256` | Rule 2 only: the SPKI hash of the listed key the signature verifies under |
| `keyUse` | `tls` or `codeSigning`: the use of the listed key, which chooses the Fix |
| `rule` | `1` or `2` |
| `kind` | `compromisedCaKey` |

Values are lowercase hex without colons. The JSON report carries them in the finding's `metadata`, SARIF in the result's `properties`, and the text report on its `SPKI SHA-256:`, `Certificate SHA-256:` and `Signed by:` rows.

## Listed keys

Each key is listed by its SPKI hash and by the SHA-256 of each certificate known for it, in hex and in base64. For the six TLS keys, the base64 SPKI hash is the `pubKeyHash` Mozilla's OneCRL publishes. Each key has two certificates, one issued under an emSign root and one cross-signed copy; both carry the same key, so rule 1 matches both. The certificates are in [`pkg/patterns/testdata/trust`](../../pkg/patterns/testdata/trust), each file named by its SHA-256.

<!-- trust-key-table:start (written by go generate ./pkg/patterns) -->

| Key | Use | Value | SHA-256 (hex) | SHA-256 (base64) |
|-----|-----|-------|---------------|------------------|
| EM OV TLS CA - G3B | tls | SPKI | `43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b` | `Q7/6GdbvZRRR9oQeAZkx6W9vLq7/KKtLbxzkV23icXs=` |
| EM OV TLS CA - G3B | tls | Certificate | `5f1ded4dd590af74631290cf073b122a2aac6a1fa479778a0bd43579bd832699` | `Xx3tTdWQr3RjEpDPBzsSKiqsah+keXeKC9Q1eb2DJpk=` |
| EM OV TLS CA - G3B | tls | Certificate | `98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b` | `mLiWYlwMIwre7D6yz2qtUAHs+RVqaGROgjdM5YM7wls=` |
| EM DV TLS CA - G3C | tls | SPKI | `49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f` | `Sd01PcK5GaN3BkURfQ5gwWEV59G8JZ7v5zSwDqQ0/l8=` |
| EM DV TLS CA - G3C | tls | Certificate | `0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19` | `AWTXzq5buQnCcq8VH/RLEXeum0fZQkuU8dlVjDCTTRk=` |
| EM DV TLS CA - G3C | tls | Certificate | `62b7f9868263f72f6911fc78ceaf72c1979158b7368bf648683bb2aa39b02e72` | `Yrf5hoJj9y9pEfx4zq9ywZeRWLc2i/ZIaDuyqjmwLnI=` |
| EM EV TLS CA - G3C | tls | SPKI | `5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0` | `XAZgorFkkQ2P9YnBjhRVLp4Owjfc7+LLc21BpIEfgaA=` |
| EM EV TLS CA - G3C | tls | Certificate | `432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3` | `Qy7CXw0o3pAG2Xv3UvF7uyzUH2aZM/ywctmhFI0CYfM=` |
| EM EV TLS CA - G3C | tls | Certificate | `fd9d5c2dbbd4995ab69b8d50c439d9527b00529199c2fd01b2174eb58f07021f` | `/Z1cLbvUmVq2m41QxDnZUnsAUpGZwv0BshdOtY8HAh8=` |
| EM OV TLS CA - G3C | tls | SPKI | `63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8` | `Y+zv7kMdSVI7wRNsTnLQIGpHcIbK9gbNXPAlaGwQnPg=` |
| EM OV TLS CA - G3C | tls | Certificate | `7485b51c0ed192878fa1d2f948fb529ae1842cc5086c4b67f7be5b2039de9489` | `dIW1HA7RkoePodL5SPtSmuGELMUIbEtn975bIDnelIk=` |
| EM OV TLS CA - G3C | tls | Certificate | `cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f` | `y24VFlrIAumz+ZPxbCXUH06Bwh695xrhsBKsAL+cfD8=` |
| EM EV TLS CA - G3B | tls | SPKI | `e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41` | `4CVMf83CZeLw+KQo2rt1q0rgObSHLWL17lfwh31aikE=` |
| EM EV TLS CA - G3B | tls | Certificate | `579480aea166290bd3c643589e795fc0d0e54e86505d180f1dff99efd3199512` | `V5SArqFmKQvTxkNYnnlfwNDlToZQXRgPHf+Z79MZlRI=` |
| EM EV TLS CA - G3B | tls | Certificate | `e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838` | `51aP5uEjMfT9feYdpMdVnQ+OsZKiGNR0GjunUYQzODg=` |
| EM DV TLS CA - G3B | tls | SPKI | `ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105` | `6+1kdcLC2A/LGZ8/6N1uazzmC3frFdTkLD3sDG9bUQU=` |
| EM DV TLS CA - G3B | tls | Certificate | `42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493` | `QsSszRLE9ZWXkl4aCKepAQJghUOAkwjVDsQn4Ri6FJM=` |
| EM DV TLS CA - G3B | tls | Certificate | `45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fcddbe` | `RaiD80mu39Xzpkm1SY/7EhcSuotEjz8qkdvFp2b83b4=` |
| EM OV CS CA - G3C | codeSigning | SPKI | `92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30` | `ksBj1n6PFNtx0ojhEmb/2vacvxFfe6sU87wvaNJeDjA=` |
| EM OV CS CA - G3C | codeSigning | Certificate | `4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1` | `SyRgpGb5X9QBE7zcyizrKbOwk5Id5FR02n30iHTGMLE=` |
| EM OV CS CA - G3C | codeSigning | Certificate | `84112972b8e59d14560ae7e7119654474aad119990cf3722bfc1e3b91615e1fd` | `hBEpcrjlnRRWCufnEZZUR0qtEZmQzzciv8HjuRYV4f0=` |
| EM OV CS CA - G3B | codeSigning | SPKI | `ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6` | `7E/6GtCsiAgTFLeq/+9qkfl81XKRu1umhsVBX1609rY=` |
| EM OV CS CA - G3B | codeSigning | Certificate | `9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4` | `njneKIEnOswiWhSccro+D1FCSWNmmrYz7h3H312wZ7Q=` |
| EM OV CS CA - G3B | codeSigning | Certificate | `a496e23ac0cab8155fc9b117b97eae368efcbb9041aec8804d5a308d2d01c2d8` | `pJbiOsDKuBVfybEXuX6uNo78u5BBrsiATVowjS0Bwtg=` |

<!-- trust-key-table:end -->

## Dates

- 2026-10-17: the key compromise is reported in Mozilla Bug 2083449.
- 2026-10-18: eMudhra revokes the eight intermediates.
- 2026-10-27: Chrome's removal of emSign ECC Root CA - G3 for all devices, reported as [TRUST-DISTRUSTED-ROOT-001](trust-distrusted-root.md).

## Verify

The finding's `Verify:` line recomputes its matched value from the scanned file with openssl and POSIX tools only, and makes no network request. It prints the bare lowercase hex value, the same under OpenSSL and LibreSSL. In the commands below, `FILE` is the file the finding names and `LINE` is the line of its `-----BEGIN CERTIFICATE-----` header.

```sh
# Rule 1: print the certificate's SPKI hash
awk "NR>=$LINE" "$FILE" | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n'
```

```sh
# Rule 2: print the certificate's SHA-256
awk "NR>=$LINE" "$FILE" | openssl x509 -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n'
```

For rule 2, confirm the signature against the listed certificate whose SPKI hash is the finding's `issuerSpkiSha256`. `LISTED` is that certificate's file from the directory above. This needs OpenSSL: the `verify` command of LibreSSL has neither option.

```sh
# Rule 2: confirm that the listed key signed the certificate (OpenSSL)
awk "NR>=$LINE" "$FILE" | openssl x509 -out flagged.pem
openssl verify -no_check_time -partial_chain -trusted "$LISTED" flagged.pem
```

It prints `flagged.pem: OK` when the listed key signed the certificate.

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

An SPKI hash from the table means the server sends a listed intermediate. A server that sends only its own certificate may still have been issued by one: check `served-1.pem` as for rule 2, in place of `flagged.pem`.

## Fix

- TLS key (`keyUse` `tls`): Replace the chain with one issued by a CA none of whose keys is listed, and remove this certificate from any bundle or pin set you ship.
- Code-signing key (`keyUse` `codeSigning`): Re-sign the artifacts with a certificate from a CA none of whose keys is listed and republish; a verifier that checks revocation rejects signatures under this key.

## Sources

- Mozilla Bug 2083449: <https://bugzilla.mozilla.org/show_bug.cgi?id=2083449>
- Google's post on Chrome and Android: <https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/>
