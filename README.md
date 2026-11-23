# Visiblaze IaC identity map

Connects a failing cloud resource in Visiblaze to the line of Terraform that declared it.

```
S3 bucket does not have event notifications enabled
  acme-prod-app-logs → infra/modules/storage/main.tf:42
```

## What is sent

Six fields per resource, and nothing else:

```json
{
  "address":    "module.storage.aws_s3_bucket.app_logs",
  "module":     "module.storage",
  "type":       "aws_s3_bucket",
  "name":       "app_logs",
  "index_key":  "",
  "native_ids": ["acme-prod-app-logs", "arn:aws:s3:::acme-prod-app-logs"]
}
```

## What is not sent

Your Terraform state. Your plan. Your source code. Any attribute value.

That is not a policy promise, it is how the script works: it **constructs** a new object from a
fixed set of identifier fields rather than stripping fields out of yours. A filter fails open —
anything it did not anticipate passes through. A constructor fails closed: an attribute nobody
thought about cannot appear in the output, because nothing ever writes it there.

We measured why this matters. Against a real OpenTofu 1.11 workspace with one secret planted:

| Artifact | Distinct JSON paths carrying the secret |
|---|---|
| `terraform.tfstate` | 6 |
| `terraform show -json <plan>` | **23** |
| `tfplan` (the binary) | a zip containing full state, the previous state, **and your `.tf` source** |

The plan is a *superset* of state's exposure, not a redaction of it — and the sensitivity flags
cannot be used to scrub it, because a computed attribute carried the secret in cleartext while
its `sensitive_values` entry was empty. So there is no safe document to hand a vendor. This
action sends none of them.

`extract-iac-identity-map.sh` is ~200 lines of shell and jq **so that you can read it**. That is
also why this is a composite action rather than a Docker one: it runs on your runner, with no
image you would have to take on trust.

## There is no secret to configure

Authentication is GitHub's own OIDC. The action mints a token that lives for minutes and states
cryptographically which repository produced it, so **nothing is stored in your repository
secrets** — there is nothing to rotate, nothing to leak, and a token captured from a log cannot be
replayed against anyone else's tenant.

What this costs you is one line: `permissions: id-token: write` on the job. Without it GitHub will
not mint the token and the action stops with a message saying so.

One-time setup on our side: your Visiblaze admin authorises your organisation (or a single repo)
for your tenant. Until they do, the action gets a `403` telling you exactly that.

## Usage

```yaml
jobs:
  plan:
    permissions:
      id-token: write        # required — lets the action mint its own short-lived token
      contents: read
    steps:
      - name: Terraform plan
        run: terraform plan -out tfplan          # you already have this

      - name: Send identity map to Visiblaze
        uses: Visiblaze/iac-identity-map@<commit-sha>
        with:
          tenant:  ${{ vars.VISIBLAZE_TENANT }}
          api-url: ${{ vars.VISIBLAZE_INGEST_URL }}
          label:   prod/eu-west-1
```

Both `tenant` and `api-url` come from us when your organisation is authorised. Neither is a secret —
they are identifiers, not credentials, so repository *variables* are the right home for them rather
than secrets.

**Pin to a commit SHA, not a tag.** A tag is mutable — whoever controls this repo can move `v1`
under you. We would rather you did not have to trust us that far, and Visiblaze pins third-party
actions the same way.

### Start with a dry run

```yaml
  with:
    tenant:  ${{ vars.VISIBLAZE_TENANT }}
    api-url: ${{ vars.VISIBLAZE_INGEST_URL }}
    dry-run: true
```

Extracts, prints the first rows, uploads nothing. Read the log, then remove the flag. A dry run
needs no `id-token` permission, because it never authenticates.

## Inputs

| Input | Default | Notes |
|---|---|---|
| `tenant` | — | **Required.** A map seeded against the wrong tenant is not recoverable by re-running. |
| `working-directory` | `.` | The folder holding your root module (where you ran `init` and `plan`), relative to the repository, e.g. `terraform/`. `plan-file` and `plan-json` are read relative to it. A job's `defaults.run.working-directory` does not apply inside an action, so a Terraform folder other than the root must be named here. |
| `api-url` | — | **Required.** The ingest endpoint we give you. There is deliberately no default: the endpoint depends on which region your workspace lives in, and a default would be frozen the moment you pin a commit SHA — so a wrong one could never be corrected for anyone already pinned. |
| `label` | the repository | What your team reads in *"searched **&lt;label&gt;** as of &lt;date&gt;"*. Name the **workspace** — `prod/eu-west-1`, not `acme/infra`. The repo name is a poor label for a repo holding several workspaces. |
| `plan-file` | `tfplan` | The output of `plan -out`. Must be inside the checkout or `RUNNER_TEMP`, and not a symlink. |
| `plan-json` | — | Use if your pipeline already rendered `show -json`. Same location rule. |
| `binary` | `terraform` | Set to `tofu` for OpenTofu. Only these two are accepted (a path to either is fine). |
| `fail-on-error` | `false` | See below. |
| `dry-run` | `false` | Extract and report; send nothing. |

Booleans accept `true`/`false`, `yes`/`no`, `1`/`0` and `on`/`off`; anything else, an `api-url` this
action may not post to, a `binary` that is not terraform or tofu, or a plan outside this job's files
fails the job whatever `fail-on-error` says.

On a pull request from a **fork** GitHub issues no OIDC token: the map is extracted, nothing is
sent, a warning says so, and the job is not failed.

There is no `token` input. If you are looking for one, see the section above.

## Large workspaces

The map is gzipped and sent in chunks of 10,000 resources. Measured at ~297 bytes per resource,
a 50,000-resource workspace is 13 MB of JSON — more than a single request can carry — and
compresses to roughly 1/24th of that.

Chunking is ordered so a failure is safe: resources are written first and the *completeness
marker* only after the final chunk. If a run dies halfway, your index reads as **incomplete** and
every resource reports "not checked". It never reports the resources that did not arrive as
having no code behind them. If a chunk fails, the action stops immediately rather than sending the
remaining ones.

### Why `fail-on-error` defaults to false

A provenance upload is an observability feature. **It must never be the reason your deploy
pipeline goes red.** If the extraction or the upload fails, the step logs a warning and the job
continues. Set it to `true` if you would rather find out loudly.

## Where this step has to go

In the **same job** as `terraform plan`, after it.

Not a separate job, not a scheduled workflow, not on our side. `plan` needs your state backend
and your cloud credentials; this step needs neither — it reads a file that job already wrote.
That is the whole reason adding it grants us no access you have not already granted that job.

## What happens on a fresh workspace

A plan for a workspace that has never been applied carries no `prior_state`, so there is nothing
deployed to map. The action reports `skipped-no-prior-state` and sends nothing.

This case is handled explicitly rather than falling through as "zero resources", because an empty
map would tell Visiblaze that every cloud resource you own has no code behind it — and that reads
in the product as *"someone built this by hand"*. Silence is the honest answer; a confident empty
one is not.

## Outputs

| Output | Values |
|---|---|
| `resources` | Count of resources sent |
| `status` | `sent`, `dry-run`, `skipped-no-prior-state`, `failed` |

## Other CI systems

**Uploading is GitHub Actions only today.** The credential is a GitHub Actions OIDC token, and
GitLab, Jenkins and CircleCI cannot mint one. We would rather say that plainly than publish a
`curl` recipe that cannot authenticate. Support for other providers is a credential problem, not
an extraction problem — tell us which one you need.

Extraction already works anywhere. `extract-iac-identity-map.sh` is a standalone script with no
dependency on this action or on GitHub; vendor it and run it wherever your plan is produced:

```bash
terraform show -json tfplan \
  | ./extract-iac-identity-map.sh --tenant "$VISIBLAZE_TENANT" --out identity-map.json
```

Exit codes — the non-zero ones are distinguished on purpose, because "nothing to send" and
"could not read the input" call for different reactions:

| Code | Meaning |
|---|---|
| `0` | Success; the map was written |
| `1` | Usage error, or `jq` is not installed |
| `2` | The plan carries no prior state — the workspace has never been applied. Not an error |
| `3` | Prior state was read, but it holds no resource with a joinable identifier |
| `4` | The input produced no usable output: empty, truncated, or not a `show -json` document |

Nothing is written on any non-zero code. In particular, an empty or unparseable input is **never**
reported as an empty map — a complete-but-empty map posted to Visiblaze is a licence to report
every cloud resource you own as having no code behind it.

The output is a bare JSON array. The endpoint takes an object — `{"label": "...", "writer": "...",
"resources": [...]}` — because `label` is what your team reads as the source that was searched,
and there is no honest default for it.
