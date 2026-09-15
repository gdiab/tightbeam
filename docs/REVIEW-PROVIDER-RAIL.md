# Prefer a different provider for code review

This opt-in rail requires a recorded coordinator decision before assigning a
same-provider code reviewer. It does not determine provider availability or judge
the quality of the coordinator's evidence.

## Policy

Try qualified, permitted reviewers from a different provider first, preserving the
org's preference order within that group. If none can run, use the same-provider
group in preference order. A different reviewer session is always required.

The rail applies when creating a linked review of a code assignment. It does not
change spec reviews, other effect classes, existing review assignments, or the
completion requirement for a linked clean review. A provider recovering later does
not invalidate an accepted review.

## Same-provider fallback

1. Record the failed attempts or configuration restrictions on the coding
   assignment using existing progress/verdict attestations. Cite concrete observations
   and report artifacts where appropriate. Do not invent failures or perform paid
   probe turns solely to satisfy this rail.
   The coding holder may file progress; a coordinator can file a verdict such as
   `review-provider-unavailable` to record its own observations.
2. The session that opened the coding assignment, or its opening/owning human user,
   files a `review-provider-fallback-approved` verdict on that assignment. Producer
   and proposed reviewer sessions cannot authorize themselves. An unrelated session
   cannot authorize merely because it belongs to the same user or has a coordinator
   role name.
3. The same authenticated principal assigns the named reviewer using the exact
   assignment key in the decision. The ordinary assignment idempotency ledger makes
   retries, including concurrent retries, return the same assignment.

The verdict's `--note` is a JSON object:

```json
{
  "version": 1,
  "reviewer_session": "REVIEWER_SESSION",
  "assignment_key": "UNIQUE_REVIEW_ATTEMPT_KEY",
  "reason": "Why no qualified different-provider reviewer could run",
  "evidence_attest_ids": ["EARLIER_ATTEST_ID"]
}
```

Example, from the opening coordinator's session:

```sh
tightbeam attest CODE_ASSIGNMENT --kind verdict \
  --verdict review-provider-fallback-approved \
  --note '{"version":1,"reviewer_session":"REVIEWER_SESSION","assignment_key":"UNIQUE_REVIEW_ATTEMPT_KEY","reason":"The permitted alternative-provider routes failed; see the cited observation.","evidence_attest_ids":["EARLIER_ATTEST_ID"]}'

tightbeam assign --subject 'Review code' --session REVIEWER_SESSION \
  --reviews CODE_ASSIGNMENT --key UNIQUE_REVIEW_ATTEMPT_KEY
```

Evidence references must be nonempty and unique, point to earlier progress/verdict
attestations on this same coding assignment, and have nonblank notes. Fallback
decisions cannot cite other fallback decisions as their evidence. The authorization
is bound to the assignment, reviewer, filing principal, and attempt key; it is not a
general exemption for the provider or org. It remains valid for that attempt until
withdrawn. Do not reuse an attempt key for new work.

To withdraw an unused authorization, the same author files
`review-provider-fallback-withdrawn` with the same `version`, `reviewer_session`, and
`assignment_key`. The latest matching decision wins. A later approval may authorize
the attempt again. Withdrawal does not revoke an already created review assignment.
Like other dispatch rails, the decision is a snapshot at evaluation time; a
concurrent withdrawal does not retroactively cancel an in-flight accepted operation.

## Completion coordination and automatic assignments

This compatible build retains the existing completion remedy, which assigns the
bound reviewer role. That assignment passes through the same rail. If its
reviewer has the same provider, the assignment is denied with the selection/fallback
instructions. Use `on_rule_denied = "surface"` to surface that denial. The opening
coordinator then selects a different provider or files the fallback decision and
assigns the reviewer directly. A remedy's process identity cannot impersonate a
coordinator or spend its approval.

## Rule facts

| Fact | Meaning |
| --- | --- |
| `assign.review_provider_relation` | `different`, `same`, `self`, or `unknown` for a resolved linked code review; otherwise absent |
| `assign.review_provider_fallback_authorized` | Whether this caller has a valid scoped decision for this same-provider assignment; otherwise false, or absent outside scope |

Provider comparison uses the code assignment's captured `holderProvider` and the
proposed reviewer's recorded provider. Changing harness or model names does not
change this comparison. Unknown provider metadata must be resolved; it is not a
fallback authorization. No provider names or model order are compiled into the
facts.

## Installation and rollback

This deployment branch is a private extension of source `84dd13e3`, retaining its
`cursor-harness-v1` database format. It does not migrate the org to the 0.1.9 schema
or modify the upstream release branch/tag.

First deploy a build containing these two facts. Then install
[`examples/review-provider.toml`](examples/review-provider.toml) into the org's
`identity/rules/` through its normal identity publication/reload workflow. Do not
install it on an older build: unknown rule facts are rejected. Refresh coordinator
guidance to include the policy and fallback instructions.

The example is deliberately outside the default shipped rules, so upgrading alone
does not impose a provider policy on every org. To disable it, remove the opt-in
rule file through that same workflow. Existing attestations remain as an audit
record; no schema migration or evidence deletion is needed.

The coordinator is accountable for the truth and completeness of the fallback
reason. This rail verifies authorization and recorded evidence, not the claim that
all alternative providers are unavailable.
