# JAR Surface Auditor

**Portfolio area:** [Software Development](https://github.com/alefkaue#desenvolvimento-de-software) · **Context:** Personal project

**Java · offline defensive analysis · original personal portfolio project**

Inspect Java archive structure and deployment metadata without loading classes or extracting archive entries.

[Português](README.pt-BR.md) · [Design and limits](docs/design.md) · [Executed example output](docs/demo-output.txt)

## Run and test

JDK 21+ and PowerShell 7 for build.ps1. No Maven or external libraries. The script compiles with --release 21 and packages a CLI JAR. Tests are a real dependency-free executable harness.

```console
./build.ps1 -Test
java -jar build/jar-surface-auditor.jar OWNED.jar reports 21
```

## Features

- Flags traversal/absolute entry paths, normalized name collisions, nested archives and suspicious expansion metadata.
- Inspects bounded class headers for base-runtime compatibility while accounting for multi-release packaging.
- Reviews external manifest classpaths; signature artifacts never become a claim of verified trust.
- Produces JSON/Markdown findings with an input hash; no external libraries or recursive archive execution.

## Evidence and limits

This is static metadata inspection, not a malware detector, full bytecode verifier, signature validator or CVE feed. Nested archives are explicitly not assessed. SHA-256 identifies a file, not its authenticity.

The committed examples/output files come from synthetic local runs. They are not customer results,
professional assessments or demonstrations against third-party systems. Input paths and archive names
can still be sensitive: keep real reports private. No account, service or network configuration is changed.

## Engineering

Parsing, decisions and output are separate from CLI argument handling. Tests cover positive cases,
ambiguous evidence and malformed data. GitHub Actions builds/tests on Windows and Linux with
read-only repository permissions and actions pinned by commit. See docs/tests.txt for the recorded local run.

Built by Alef Kaue Santos Nunes with AI assistance. This does not claim professional experience or
independent vulnerability discovery. MIT covers original code and documentation.

## Reference

- [Official format/API reference](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/zip/ZipFile.html)
