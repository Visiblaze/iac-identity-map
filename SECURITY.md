# Security policy

## Why this repository warrants a policy of its own

The action in this repository runs inside **your** CI job, and that job holds more than most:
a GitHub OIDC token minted with `id-token: write`, and whatever cloud credentials your
Terraform needs. Code in that position deserves to be read before it is trusted, which is why
this repository is public and Apache-2.0 licensed rather than a prebuilt binary.

Two design decisions follow from that, and both are load-bearing:

- **Terraform state never leaves your machine.** The script reads `tofu show -json` (or
  `terraform show -json`) on stdin and emits only `address`, `module`, `type`, `name`,
  `index_key` and `native_ids`. It is a reduction, not an upload. State and plan JSON both
  carry attribute values in plaintext — a single planted secret was observed at 6 distinct
  paths in a state file and 23 in a plan — so neither is ever transmitted.
- **No long-lived secret is stored in your CI.** Authentication is a short-lived
  GitHub-signed OIDC token, verified server-side against GitHub's published keys. There is no
  API key to leak, rotate, or exfiltrate from your runner.

## Reporting a vulnerability

Please report privately, not in a public issue.

Use **[GitHub private vulnerability reporting](https://github.com/Visiblaze/iac-identity-map/security/advisories/new)**
on this repository. If that is unavailable to you, email **security@visiblaze.com**.

Please include enough to reproduce: the version or commit SHA you ran, the Terraform/OpenTofu
version, and a redacted example of the input that triggers it. **Do not send us real state,
real plan output, or real secrets** — a minimal synthetic input is more useful and safer for
both of us.

### What to expect

| | |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment | within 10 business days |
| Fix or mitigation plan | communicated with the assessment |

We will tell you what we conclude, including when we conclude a report is not a vulnerability
and why. If you would like credit in the advisory, say so and give us the name to use.

## Scope

**In scope** — everything in this repository:

- `extract-iac-identity-map.sh`, particularly anything causing it to emit a field it should
  not, or to write output it should have refused to write
- `action.yml`, particularly command injection through inputs, or leakage of the OIDC token
- Any path where a failure is reported as success, or where output is written despite an error

**Out of scope here** — but still wanted, via the same channels:

- The Visiblaze platform and its APIs. Those are covered by your commercial agreement, not by
  this licence, and are not part of this repository.
- Findings that require an attacker to already control the runner or the Terraform state.
- Vulnerabilities in `jq`, `bash`, Terraform or OpenTofu themselves. Report those upstream; tell
  us if this action's usage makes one materially worse.

## Supported versions

Pin to a **commit SHA**, not a tag or branch:

```yaml
- uses: Visiblaze/iac-identity-map@<full-40-char-sha>
```

A tag is a movable pointer. Pinning a SHA means the code that runs beside your cloud
credentials cannot change without you changing it. Only the latest commit on `main` receives
fixes; there are no maintained release branches.
