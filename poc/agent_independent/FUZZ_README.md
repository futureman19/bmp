# Independent BMP-0005 adversarial conformance / fuzz gate

Deterministic, offline adversarial testing for Qwen's independent Node implementation. This harness is derived from the normative BMP-0005 specification, explicitly published vector JSON, and `agent_independent/` only. It does not read, import, invoke, or claim differential coverage of the Python reference implementation.

## Run

Requires Node.js 18+ (for `structuredClone`). No install, network, wallet, or credentials are needed.

```bash
cd poc/agent_independent
node fuzz_conformance.js
node test_parity.js
```

Optional modes:

```bash
node fuzz_conformance.js --nightly  # larger deterministic corpus
node fuzz_conformance.js --raw      # also write fuzz_raw/corpus.json
```

The default gate takes about eight minutes on the development host. Raw output is intentionally ignored by Git. The default command rewrites `fuzz_manifest.json`, prints its SHA-256, and exits nonzero on any failed expectation or unexpected error. A gate run consists of two executions with byte-identical manifest files and hashes, plus the existing parity suite.

## Default corpus

- Seed: `0x424d5033` (`sfc32`; no `Math.random`, wall-clock, or environment data in artifacts).
- **24,754 total cases:** 24,665 mutated/property cases, 36 published-positive executions, 33 published negatives, and 20 non-vacuity controls.
- Stable IDs: `<class>-<five-digit sequence>` in deterministic generation order.
- Exact expected rejection codes/layers; blanket exceptions never count as passes. Unknown categories abort case generation or manifest emission rather than being relabeled `ERROR`.
- Accepting mutations are tagged and counted. Explicit `acceptReason` annotations cover selected legal behaviors (Unicode free text, optional REJECT reason, exact-byte replay, task-cap equality, and distinct-message-ID PROOFs); not every accepting boundary mutation has an individual annotation. Multiple valid rejection categories are explicit arrays where one input violates multiple rules.

Coverage classes include frame/length/truncation, JSON/JCS/UTF-8, principal and target binding, Base64/schema, signatures/low-S, freshness windows, replay/thread/role/parent binding, published payment transaction data, encoder consistency, and property checks. The compact manifest records counts by class, rejection layer and code, tagged accepting mutations, explicit `acceptReason` annotations, failures, and stable result rows. Published payment fixtures are mandatory: missing data aborts the gate, and computed txid/output/value must match published known answers.

The corpus treats non-ASCII free text as legal where the spec defines opaque UTF-8. It also permits distinct PROOF envelopes for one subject when their message IDs differ: §9.8 requires exact-byte idempotency and same-message-ID conflict rejection, not subject-level proof deduplication.

## Scope limits

This is an independent conformance/adversarial suite, not a Stable-protocol certification. It covers wire/JSON/signature/address/target/binding/window/schema behavior and transaction **data extraction** from published fixtures. It does not implement or claim payment-shape validation, SPV/BEEF verification, Python differential execution, live-network behavior, wallet integration, or mainnet evidence. Those layers require their own reviewed gates.

`fuzz_manifest.json` is the expected compact result artifact. `fuzz_raw/` is optional diagnostic output and must not be committed.
