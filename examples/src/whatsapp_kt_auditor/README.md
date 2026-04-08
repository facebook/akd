# WhatsApp Key Transparency Auditor

An independent auditor for verifying [WhatsApp key transparency](https://engineering.fb.com/2023/04/13/security/whatsapp-key-transparency/) audit proofs. This tool fetches published audit proofs from WhatsApp's CloudFront-backed storage and cryptographically verifies each epoch's append-only proof using the [AKD](https://github.com/facebook/akd) library.

## Log Versions

| Log | Epochs | Date Range (PT) | Description |
|-----|--------|-----------------|-------------|
| **v2** (default) | 722,606+ | 2026-03-13 18:41 PT – present | The current WhatsApp KT log, actively published to |
| **v1** | 1 – 2,026,881 | 2023-02-14 14:45 PT – 2026-03-13 08:37 PT | The legacy WhatsApp KT log (no longer updated) |

The **v1** log contains historical audit proofs from WhatsApp's original key transparency deployment, covering epochs 1 through 2,026,881. It is no longer being published to. The **v2** log is a separate log starting from epoch 722,606 onward; epoch numbers between the two logs are not correlated. The v2 log is the log that WhatsApp actively publishes to going forward. Both logs use the same cryptographic configuration and proof format, so the auditor verifies them identically.

By default, the auditor operates against the **v2** log. Use `--log v1` to audit proofs from the legacy log.

## Usage

### Audit the latest epoch

```bash
cargo run -p examples --release -- whatsapp-kt-auditor -l
```

### Audit a specific epoch

```bash
cargo run -p examples --release -- whatsapp-kt-auditor -e 722610
```

### Interactive mode

Load all available epochs and choose which to audit interactively:

```bash
cargo run -p examples --release -- whatsapp-kt-auditor -i
```

### Auditing the legacy log

Pass `--log v1` before the subcommand to audit the legacy log:

```bash
cargo run -p examples --release -- whatsapp-kt-auditor --log v1 -l
cargo run -p examples --release -- whatsapp-kt-auditor --log v1 -e 42
```
