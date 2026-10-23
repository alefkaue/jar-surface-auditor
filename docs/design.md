# Design and trust boundaries

Inspect Java archive structure and deployment metadata without loading classes or extracting archive entries.

- Flags traversal/absolute entry paths, normalized name collisions, nested archives and suspicious expansion metadata.
- Inspects bounded class headers for base-runtime compatibility while accounting for multi-release packaging.
- Reviews external manifest classpaths; signature artifacts never become a claim of verified trust.
- Produces JSON/Markdown findings with an input hash; no external libraries or recursive archive execution.

This is static metadata inspection, not a malware detector, full bytecode verifier, signature validator or CVE feed. Nested archives are explicitly not assessed. SHA-256 identifies a file, not its authenticity.

The source snapshot is evidence supplied by the operator, not remote attestation. A metadata flag or heuristic is not proof of an attack. Tests use fixtures constructed by this repository and do not contact external targets. Do not execute or extract untrusted samples as a way to use this tool.
