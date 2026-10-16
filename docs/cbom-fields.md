# CBOM fields

This page lists every field that `cryptoscan scan <path> --format cbom` writes,
the line in `pkg/reporter/cbom.go` that sets it, and how the output lines up
with the NTIA minimum elements for a software bill of materials. It also lists
the CycloneDX 1.6 fields the reporter does not write yet, so you know what not
to expect in a CBOM from CryptoScan.

## How this page is checked

`pkg/reporter/cbom_fields_test.go` reads the tables on this page. It runs the
real scanner, with the default scan settings, over a small project that
produces algorithm, key material, certificate, TLS and hybrid findings,
generates a CBOM from the result, and then checks:

- every row marked `emitted` or `partial` has a non-empty value at its path in
  that CBOM;
- every row marked `not emitted` has no value there, so a change that starts
  writing a field also has to update its row.

A row that claims more than the reporter writes fails the test. To run it:

```bash
go test ./pkg/reporter -run 'CBOMFields|FieldsDocumented|OverclaimedField'
```

The CycloneDX enum and format checks for the values the reporter writes live in
`pkg/reporter/cbom_schema_test.go`. Neither test validates a whole CBOM against
the CycloneDX JSON schema.

## Reading the tables

| Status | Meaning |
|---|---|
| `emitted` | Written whenever the condition in the row holds. |
| `partial` | Written for some of the components it applies to. The row says which. |
| `not emitted` | Not written by any scan today. The row names a follow-up item from the list at the end. |

A path segment ending in `[]` means each element of that array. Line numbers
refer to `pkg/reporter/cbom.go` as of the change that last edited this page.

The CycloneDX 1.6 JSON reference shows the component definition once, inside
`metadata.tools`, and `components[]` uses that same definition. The links for
`components[]` fields therefore point into the `metadata.tools` section of the
reference.

## Fields in the document and its metadata

| JSON path | Status | Written when | CycloneDX 1.6 | Set in `cbom.go` |
|---|---|---|---|---|
| `bomFormat` | emitted | Every CBOM. Value `CycloneDX`. | [bomFormat](https://cyclonedx.org/docs/1.6/json/#bomFormat) | 523 |
| `specVersion` | emitted | Every CBOM. Value `1.6`. | [specVersion](https://cyclonedx.org/docs/1.6/json/#specVersion) | 524 |
| `serialNumber` | emitted | Every CBOM. A random `urn:uuid` value, new on each run. | [serialNumber](https://cyclonedx.org/docs/1.6/json/#serialNumber) | 525, 651-659 |
| `version` | emitted | Every CBOM. Value `1`. | [version](https://cyclonedx.org/docs/1.6/json/#version) | 526 |
| `metadata.timestamp` | emitted | Every CBOM. The time of the run in UTC, RFC 3339. | [metadata.timestamp](https://cyclonedx.org/docs/1.6/json/#metadata_timestamp) | 528 |
| `metadata.tools[].vendor` | emitted | Every CBOM. Value `CSNP`. | [tools, legacy form](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i1_items_vendor) | 531 |
| `metadata.tools[].name` | emitted | Every CBOM. Value `CryptoScan`. | [tools, legacy form](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i1_items_name) | 532 |
| `metadata.tools[].version` | emitted | Every CBOM. The CryptoScan version. | [tools, legacy form](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i1_items_version) | 533 |
| `metadata.component` | emitted | Every CBOM. It holds a summary named "Cryptographic Inventory Summary" with the migration readiness score, not the scanned project. See F1. | [metadata.component](https://cyclonedx.org/docs/1.6/json/#metadata_component) | 512-520, 536 |
| `metadata.authors` | not emitted | The person or organization that ran the scan is not recorded. See F7. | [metadata.authors](https://cyclonedx.org/docs/1.6/json/#metadata_authors) | not in the reporter |
| `metadata.manufacturer` | not emitted | See F7. | [metadata.manufacturer](https://cyclonedx.org/docs/1.6/json/#metadata_manufacturer) | not in the reporter |
| `services[]` | not emitted | Declared and never assigned. See F8. | [services](https://cyclonedx.org/docs/1.6/json/#services) | declared at 42 |
| `dependencies[]` | not emitted | The code links a hybrid construction to its parts only when the algorithm name carries both of them. No detection pattern produces such a name, so no dependency is written. See F3. | [dependencies](https://cyclonedx.org/docs/1.6/json/#dependencies) | 452-461, 491-509 |

The reporter writes `metadata.tools` in the legacy form, an array of vendor,
name and version. CycloneDX 1.6 still accepts that form and marks it
deprecated.

## Fields on each component

| JSON path | Status | Written when | CycloneDX 1.6 | Set in `cbom.go` |
|---|---|---|---|---|
| `components[].type` | emitted | Every component. Value `cryptographic-asset`. | [type](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_type) | 392 |
| `components[].bom-ref` | emitted | Every component. `crypto-<name>-<n>`, unique within one CBOM. | [bom-ref](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_bom-ref) | 388, 393 |
| `components[].name` | emitted | Every component. The algorithm name, or the detection pattern's name when the finding names no algorithm, as for key material and certificates. | [name](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_name) | 382-385, 394 |
| `components[].description` | emitted | Every component. The detection pattern's description. | [description](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_description) | 395 |
| `components[].version` | not emitted | Declared and never assigned. See F2. | [version](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_version) | declared at 62 |
| `components[].supplier` | not emitted | See F2. | [supplier](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_supplier) | not in the reporter |
| `components[].cryptoProperties.assetType` | emitted | Every component. Findings in the `Certificate` category are written as `certificate`, findings in the `Secret Detection` category as `related-crypto-material`, and everything else as `algorithm`, including TLS findings. | [assetType](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_assetType) | 396-398, 156-172 |
| `components[].cryptoProperties.algorithmProperties.primitive` | emitted | Algorithm assets whose finding names an algorithm. | [primitive](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_algorithmProperties_primitive) | 427-431, 239-292 |
| `components[].cryptoProperties.algorithmProperties.parameterSetIdentifier` | not emitted | Filled only when the algorithm name carries a parameter set, such as `ML-KEM-768`. The detection patterns report family names such as `ML-KEM`, so no scan reaches it. See F6. | [parameterSetIdentifier](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_algorithmProperties_parameterSetIdentifier) | 433-436 |
| `components[].cryptoProperties.algorithmProperties.classicalSecurityLevel` | partial | Algorithm assets where the pattern records a key size, or where a level can be estimated from the name. AES is written as 256 whatever key length the code uses. Omitted when neither gives a value. See F6. | [classicalSecurityLevel](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_algorithmProperties_classicalSecurityLevel) | 438-444, 355-371, 585-609 |
| `components[].cryptoProperties.algorithmProperties.nistQuantumSecurityLevel` | partial | Quantum-safe algorithm assets. When the name carries no parameter set, the value written is 1, which can understate a stronger parameter set. Omitted for algorithms that are not quantum-safe. See F6. | [nistQuantumSecurityLevel](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_algorithmProperties_nistQuantumSecurityLevel) | 446-450, 306-353 |
| `components[].cryptoProperties.algorithmProperties.executionEnvironment` | not emitted | Declared and never assigned. See F8. | [executionEnvironment](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_algorithmProperties_executionEnvironment) | declared at 89 |
| `components[].cryptoProperties.algorithmProperties.implementationPlatform` | not emitted | Declared and never assigned. See F8. | [implementationPlatform](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_algorithmProperties_implementationPlatform) | declared at 90 |
| `components[].cryptoProperties.algorithmProperties.certificationLevel` | not emitted | Declared and never assigned. See F8. | [certificationLevel](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_algorithmProperties_certificationLevel) | declared at 91 |
| `components[].cryptoProperties.algorithmProperties.mode` | not emitted | Declared and never assigned. See F8. | [mode](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_algorithmProperties_mode) | declared at 92 |
| `components[].cryptoProperties.algorithmProperties.padding` | not emitted | Declared and never assigned. See F8. | [padding](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_algorithmProperties_padding) | declared at 93 |
| `components[].cryptoProperties.algorithmProperties.cryptoFunctions` | not emitted | Declared and never assigned. See F8. | [cryptoFunctions](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_algorithmProperties_cryptoFunctions) | declared at 94 |
| `components[].cryptoProperties.certificateProperties` | not emitted | Certificate findings are written with `assetType` `certificate` and no properties block. See F5. | [certificateProperties](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_certificateProperties) | declared at 71 and 99-105 |
| `components[].cryptoProperties.protocolProperties` | not emitted | The code looks for the categories `tls` and `protocol`, but the TLS patterns use `TLS/SSL` and `Deprecated Protocol`, so TLS findings are written as algorithm assets with primitive `other`. See F4. | [protocolProperties](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_protocolProperties) | 464-473 |
| `components[].cryptoProperties.relatedCryptoMaterialProperties.type` | emitted | Key material, that is findings in the `Secret Detection` category such as a private key header. Values come from the CycloneDX enum, and anything unrecognized is written as `unknown`. | [relatedCryptoMaterialProperties.type](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_relatedCryptoMaterialProperties_type) | 418-423, 210-237 |
| `components[].cryptoProperties.relatedCryptoMaterialProperties.size` | not emitted | Copied from the finding's key size, which no key material pattern records. See F6. | [relatedCryptoMaterialProperties.size](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_relatedCryptoMaterialProperties_size) | 421 |
| `components[].cryptoProperties.relatedCryptoMaterialProperties.state` | not emitted | Declared and never assigned. See F8. | [relatedCryptoMaterialProperties.state](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_relatedCryptoMaterialProperties_state) | declared at 82 |
| `components[].cryptoProperties.oid` | partial | Algorithms whose name is in the OID table in `pkg/types/types.go`. Of the algorithm names the detection patterns report, only `RSA` is in that table today. See F6. | [oid](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_cryptoProperties_oid) | 410-413, 294-304 |
| `components[].evidence.occurrences[].location` | emitted | Every component, once per occurrence. The file path relative to the scan root. | [location](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_evidence_occurrences_items_location) | 402, 480 |
| `components[].evidence.occurrences[].line` | emitted | Every component, once per occurrence. | [line](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_evidence_occurrences_items_line) | 403, 481 |
| `components[].evidence.occurrences[].symbol` | emitted | Every component, once per occurrence. The matched text. | [symbol](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_evidence_occurrences_items_symbol) | 404, 482 |

## NTIA minimum elements

Source: *The Minimum Elements For a Software Bill of Materials (SBOM)*, United
States Department of Commerce, July 12, 2021
([PDF](https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report_0.pdf)).
The field names and descriptions below are quoted from its data fields table.
The report does not map its fields to CycloneDX paths; the mapping here is
ours.

These elements were written for software bills of materials. In a CBOM most
components are algorithms, keys or certificates rather than software packages,
so supplier and version say little about most rows. They do matter for a
cryptographic library that a project depends on.

| NTIA data field | NTIA description | JSON path | Status | Notes |
|---|---|---|---|---|
| Supplier Name | The name of an entity that creates, defines, and identifies components. | `components[].supplier` | not emitted | See F2. |
| Component Name | Designation assigned to a unit of software defined by the original supplier. | `components[].name` | emitted | The algorithm name, or the detection pattern's name for key material and certificates. |
| Version of the Component | Identifier used by the supplier to specify a change in software from a previously identified version. | `components[].version` | not emitted | Not meaningful for an algorithm, meaningful for a library dependency. See F2. |
| Other Unique Identifiers | Other identifiers that are used to identify a component, or serve as a look-up key for relevant databases. | `components[].cryptoProperties.oid` | partial | Only for algorithms in the OID table. `bom-ref` is unique within one CBOM only, so it is not counted here. See F6. |
| Dependency Relationship | Characterizing the relationship that an upstream component X is included in software Y. | `dependencies[]` | not emitted | See F3. |
| Author of SBOM Data | The name of the entity that creates the SBOM data for this component. | `metadata.tools[]` | partial | Names the tool and its vendor. The person or organization that ran the scan is not recorded. See F7. |
| Timestamp | Record of the date and time of the SBOM data assembly. | `metadata.timestamp` | emitted | |

## CISA and NIST CBOM minimum elements

As of 2026-10-16, CISA and NIST have not published minimum elements for a
CBOM, so this page makes no claim against them.

Secondary reporting says an executive order signed on 2026-06-22 directs CISA,
working with NIST, to publish them within 270 days, which would be about
2027-03-19. The order's number, section and exact deadline are NOT VERIFIED
here, because its primary text in the Federal Register has not been read.

When the list is published, this page is where CryptoScan tracks it. Each
published element gets a row in a new table, mapped to the paths above with
the same three statuses, and the same test checks those rows. Until then, the
NTIA table above is the closest published list this page could check against
its primary text.

## Follow-up work

Rows marked `not emitted` or `partial` point to one of these items. None of
them has a date.

- **F1. Describe the scanned project in `metadata.component`.** CycloneDX
  defines `metadata.component` as the component that the BOM describes. The
  reporter puts the migration readiness summary there instead. The change sets
  it to the scanned project (named after the target directory or repository
  URL, type `application`) and moves the summary to a property or to a
  component of its own. Consumers read this field, so the change comes with its
  own test.
- **F2. Supplier and version for cryptographic libraries.** The scanner reads
  library versions from dependency files, but the CBOM does not carry them, and
  no component names a supplier.
- **F3. Dependency relationships for hybrid constructions.** The reporter can
  link a hybrid to its classical and post-quantum parts only when the algorithm
  name carries both, for example `X25519` and `MLKEM`. The hybrid patterns
  report `Hybrid-KEM`, `Hybrid-TLS` and `Composite-Signature`, so no link is
  written.
- **F4. Protocol properties for TLS findings.** Match the categories the TLS
  patterns use, so that TLS findings carry `protocolProperties` with the
  protocol version.
- **F5. Certificate properties for certificate findings.** Subject, issuer,
  validity dates and signature algorithm, where the certificate can be read.
- **F6. Parameter sets, key sizes and identifiers.** The patterns report
  algorithm families such as `ML-KEM` and `AES`, so the CBOM cannot carry a
  parameter set, the size of detected key material, or an OID for most
  algorithms, and the security levels it writes for a family are estimates.
- **F7. Record who produced the CBOM.** Write `metadata.authors` or
  `metadata.manufacturer`, so the BOM names the organization that ran the scan
  and not only the tool.
- **F8. Declared fields that are never written.** `services`, the
  `algorithmProperties` fields `executionEnvironment`,
  `implementationPlatform`, `certificationLevel`, `mode`, `padding` and
  `cryptoFunctions`, and `relatedCryptoMaterialProperties.state` are declared
  in the reporter and never assigned. Each one is either filled from real
  evidence or removed from the reporter.
