#!/usr/bin/env bash
# Copyright 2026 Visiblaze
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# extract-iac-identity-map.sh — produce the Terraform identity map Visiblaze needs,
# without any state, plan or source ever leaving your network.
#
# WHY THIS EXISTS
#
# Connecting a failing cloud resource to the line of code that declared it needs exactly one
# thing: a map from Terraform address to the identifiers the cloud uses for the same resource.
# That map lives inside Terraform state — but state is not a document anyone should be shipping
# to a vendor, and neither is a plan.
#
# Measured against a real OpenTofu 1.11 workspace, with one secret deliberately planted:
#
#   terraform.tfstate           the secret appeared at  6 distinct JSON paths
#   tofu show -json tfplan      the secret appeared at 23 distinct JSON paths
#                               (the plan's prior_state contains every one of state's)
#   tfplan (the binary)         a zip carrying full state, the PREVIOUS state, and the raw .tf
#
# The sensitivity flags cannot be used to scrub any of them either: in the same probe a computed
# attribute carried the secret in cleartext while its `sensitive_values` entry was empty, and the
# entry that leaked it was a *data source* — a read, not something the workspace even manages.
#
# So there is no safe document to hand over, and the answer is not "redact the file", it is
# "never produce the file". This script runs on YOUR side, reads the plan locally, and emits six
# fields per resource: address, module, type, name, index key, and the id/arn strings the cloud
# uses. Nothing else is read. You can verify that claim by reading this file — which is the
# reason this is a 200-line shell script and not a binary you would have to trust.
#
# WHAT LEAVES: address, module, type, name, index_key, native_ids[].
# WHAT DOES NOT: every attribute value, without exception.
#
# USAGE
#
#   tofu plan -out tfplan
#   tofu show -json tfplan | ./extract-iac-identity-map.sh --tenant YOUR_TENANT_ID --out identity-map.json
#
#   # terraform works identically:
#   terraform show -json tfplan | ./extract-iac-identity-map.sh --tenant YOUR_TENANT_ID --out identity-map.json
#
#   # already applied and you only want today's inventory? state works too:
#   tofu show -json | ./extract-iac-identity-map.sh --tenant YOUR_TENANT_ID --out identity-map.json
#
# Read identity-map.json before you post it. It is pretty-printed for exactly that reason.
#
# EXIT CODES — the empty cases are split on purpose, see the "none" branch below.
#
#   0  wrote the map
#   1  usage error or jq missing
#   2  the plan carries no prior state: this workspace has never been applied
#   3  prior state read fine and holds no joinable managed resources
#   4  refused: something in the output is shaped like a value, not an identifier
set -euo pipefail

PLAN="-"
OUT=""
TENANT=""

usage() {
	cat >&2 <<'EOF'
usage: extract-iac-identity-map.sh --tenant TENANT_ID --out FILE [--plan FILE]

  --tenant ID     your Visiblaze tenant id (required)
  --out FILE      where to write the identity map; "-" writes to stdout
  --plan FILE     JSON from `tofu show -json tfplan`; default "-" (stdin)
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--out) OUT="${2:-}"; shift 2 ;;
	--plan) PLAN="${2:-}"; shift 2 ;;
	--tenant) TENANT="${2:-}"; shift 2 ;;
	-h | --help) usage; exit 0 ;;
	*) echo "unknown argument: $1" >&2; usage; exit 1 ;;
	esac
done

[ -n "$OUT" ] || { echo "--out is required" >&2; usage; exit 1; }

# --tenant is REQUIRED, and it is worth saying why it is not merely defaulted.
#
# The map is stored per tenant, keyed by Terraform address. Writing it under the wrong tenant is
# additive — it does not fail, it does not overwrite anything visible, and there is no delete
# path — so the victim tenant simply starts reporting that resources it does own have no code
# behind them. That is indistinguishable from a real finding and nobody would think to look here.
# An unstamped map used to be legal and the seed step guessed; a guess is exactly what must not
# happen with a value that cannot be taken back.
[ -n "$TENANT" ] || {
	echo "--tenant is required: an identity map written under the wrong tenant cannot be undone by re-running" >&2
	usage
	exit 1
}
command -v jq >/dev/null 2>&1 || { echo "jq is required (https://jqlang.github.io/jq/)" >&2; exit 1; }

# The temp file is not a convenience, it is the guard.
#
# jq emits its single output value only once the whole value is built, so a refusal inside the
# program prints nothing — but the shell has ALREADY created and truncated the redirect target.
# Writing straight to --out would therefore leave a zero-byte identity map next to a message
# saying we refused to write one, and the next step in the pipeline would happily post it. So jq
# writes here, the guards are checked here, and moving the file to --out is the commit.
TMP="$(mktemp "${TMPDIR:-/tmp}/iac-identity-map.XXXXXX")"
cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

# maxid bounds a plausible identifier. ARNs sit well under it; a certificate or private key does
# not. Paired with the PEM check this is a SHAPE test, deliberately not a vocabulary test:
# matching words like "password" flags 77 rows in our own dev map and every one is a false
# positive (an API route path `POST /auth/change-password`, a Lambda permission statement id, and
# the service name inside arn:aws:secretsmanager:...). A guard that cries wolf 77 times is a guard
# somebody deletes. The real control is the five-key allowlist in `ids` below, which never reads
# an attribute that could hold a secret in the first place.
jq \
	--arg tenant "$TENANT" \
	--argjson maxid 512 \
	'
# ── The allowlist ───────────────────────────────────────────────────────────────────────────
#
# Every id shape the cloud side might use for one resource. A CSPM finding names a resource by
# full ARN for most services and by bare name for a few (S3 buckets, IAM by unique id, KMS by key
# id), so emitting both shapes is what makes the join a map lookup instead of per-service string
# surgery.
#
# Five keys, by name. Nothing else in `values` is read — not iterated, not inspected, not even
# materialised into a variable.
def ids:
  (. // {}) as $v
  | [ $v.id?, $v.arn?, $v.unique_id?, $v.policy_id?, $v.key_id? ]
  | map(select(type == "string" and length > 0))
  # A CloudWatch log group ARN turns up in findings both with and without the trailing :*
  # wildcard, so carry both spellings rather than guessing which one the scanner used.
  | . + (map(select(endswith(":*")) | .[0:-2]))
  # Order-preserving dedupe, not `unique` — `unique` sorts, and an export that reorders itself
  # between runs cannot answer "did the map change since last apply".
  | reduce .[] as $x ([]; if index($x) == null then . + [$x] else . end);

# ── The constructor ─────────────────────────────────────────────────────────────────────────
#
# This BUILDS its output object rather than deleting fields from the input, and the difference is
# the whole security posture. A filter fails OPEN: the day Terraform adds an attribute nobody here
# anticipated, a delete-list quietly forwards it. A constructor fails CLOSED: an unanticipated
# attribute has no way in, because nothing copies it.
def entry($mod):
  . as $r
  # `index` is OMITTED, not null, for a resource with no count/for_each — so test for the key.
  # Reading `.index` alone would make "no index" and "index null" indistinguishable, and the
  # address `aws_s3_bucket.logs[null]` matches nothing on the code side.
  | (if ($r | has("index")) and ($r.index != null) then $r.index else null end) as $idx
  | (($r.type // "") | if . == "" then error("managed resource with no type: this is not a Terraform values document") else . end) as $type
  | (($r.name // "") | if . == "" then error("managed resource with no name: this is not a Terraform values document") else . end) as $name
  | (if $mod == "" then "" else $mod + "." end) as $prefix
  | {
      # The address Terraform itself would print, including any [index] suffix. Built from the
      # parts rather than copied from `.address` so that this field and `module` cannot disagree
      # with each other — one source of truth, or the mismatch is invisible.
      # @json quotes a string key and leaves a numeric one bare, which is exactly Terraform own
      # spelling: ["blue"] and [0].
      address:    ($prefix + $type + "." + $name
                   + (if $idx == null then "" else "[" + ($idx | @json) + "]" end)),
      module:     $mod,
      type:       $type,
      name:       $name,
      # Kept separate from the address because the CODE side has one declaration for every
      # instance — logs[0] and logs[1] are a single resource block — so the consumer strips the
      # index before matching a declaration and needs the key back afterwards.
      index_key:  (if $idx == null then "" elif ($idx | type) == "string" then $idx else ($idx | tostring) end),
      native_ids: ($r.values | ids)
    };

# ── The walk ────────────────────────────────────────────────────────────────────────────────
#
# Explicit recursion through child_modules to any depth. Deliberately not `.. | objects |
# select(has("resources"))`: that would also descend INTO resource attribute maps and pick up any
# resource that happens to have an attribute called "resources" — a filter failing open again.
# This only ever follows the one key that is a module.
def walk($mod):
  ( (.resources // [])
    # mode == "managed" only. A data source is a read, not something the workspace deployed, so
    # it has no code to be traced back to — and in our probe the data source was the entry
    # carrying the unflagged secret.
    | map(select(.mode == "managed") | entry($mod)) )
  + ( (.child_modules // [])
      | map( (.address // error("child module with no address: cannot name its resources")) as $a | walk($a) )
      | add // [] );

# ── Which document is this ──────────────────────────────────────────────────────────────────
#
# prior_state is what EXISTS. planned_values is what WOULD exist after apply, and is never read
# here: it contains unknown-until-apply placeholders and describes infrastructure that does not
# exist yet.
#
# prior_state is ABSENT ENTIRELY from a workspace that has never been applied. That case must not
# collapse into "we looked and found nothing", because downstream an empty-but-successfully-read
# map means the platform is entitled to say "there is no code behind any of your cloud" — about a
# workspace it simply never saw. Hence source:"none", carried out as data and refused by the
# wrapper with its own exit code.
. as $doc
| ( if   ($doc | has("prior_state")) then "prior_state"
    elif ($doc | has("values")) and (($doc | has("planned_values")) | not) then "state"
    else "none" end ) as $kind
| ( if   $kind == "prior_state" then ($doc.prior_state.values.root_module // null)
    elif $kind == "state"       then ($doc.values.root_module // null)
    else null end ) as $root
| (if $root == null then "none" else $kind end) as $source
| (if $root == null then [] else ($root | walk("")) end) as $all
# A resource with no identifier the cloud could ever use cannot be joined to anything, so storing
# it would grow the index without ever matching. Counted, not hidden.
| ($all | map(select((.native_ids | length) > 0))) as $joinable
| (if $tenant == "" then {} else {tenant_id: $tenant} end) as $stamp
| ($joinable | map($stamp + .)) as $rows
# Last gate before anything is written. Refusing here is not paranoia about this program — it is
# a tripwire for the day someone widens the allowlist above without thinking it through.
| ( [ $rows[] as $r
      | $r.native_ids[] as $v
      | if   ($v | contains("-----BEGIN")) then "\($r.address): PEM header in native_ids"
        elif ($v | length) > $maxid        then "\($r.address): \($v | length)-character native id (limit \($maxid))"
        else empty end ] ) as $problems
| if ($problems | length) > 0 then
    error("value-shaped strings in the identity map, refusing to emit:\n  " + ($problems[0:10] | join("\n  ")))
  else
    { source: $source,
      managed: ($all | length),
      no_native_ids: (($all | length) - ($joinable | length)),
      rows: $rows }
  end
' "$([ "$PLAN" = "-" ] && echo /dev/stdin || echo "$PLAN")" >"$TMP" || {
	echo "extract-iac-identity-map: refused, see the jq error above" >&2
	exit 4
}

SOURCE="$(jq -r '.source' "$TMP")"
MANAGED="$(jq -r '.managed' "$TMP")"
NOIDS="$(jq -r '.no_native_ids' "$TMP")"
ROWS="$(jq -r '.rows | length' "$TMP")"
IDS="$(jq -r '[.rows[].native_ids | length] | add // 0' "$TMP")"

if [ "$SOURCE" = "none" ]; then
	cat >&2 <<-EOF
		extract-iac-identity-map: this plan carries no prior state.

		That means the workspace has never been applied, so there is nothing deployed to map. It is
		NOT the same as "this workspace has no resources", and posting an empty map would let the
		platform report every cloud resource you own as having no code behind it.

		Nothing was written. Apply first, then re-run against a fresh plan.
	EOF
	exit 2
fi

if [ "$ROWS" -eq 0 ]; then
	cat >&2 <<-EOF
		extract-iac-identity-map: read prior state successfully; it holds no joinable resources.
		  managed resources     : $MANAGED
		  without an identifier : $NOIDS

		Nothing was written: an empty map is indistinguishable from a complete one once posted, and
		a complete-but-empty map is a licence to say "no code behind any of this".
	EOF
	exit 3
fi

if [ "$OUT" = "-" ]; then
	jq '.rows' "$TMP"
else
	jq '.rows' "$TMP" >"$OUT.partial" && mv "$OUT.partial" "$OUT"
fi

cat >&2 <<-EOF
	read from           : $SOURCE
	managed resources   : $MANAGED
	resources exported  : $ROWS
	native id strings   : $IDS
	skipped (no id)     : $NOIDS
	shape guard         : clean (no PEM headers, no id over 512 chars)
	wrote               : $OUT
EOF
