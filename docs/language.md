# Version 1 authorization language

This document defines this lab's semantics. It does not import another product's IAM behavior.

## Policy shape

A policy has exactly `version`, `roles`, and `rules`. Version must be 1. There are 1–16 role declarations and 0–32 rules. Identifiers match `[a-z][a-z0-9-]{0,47}`. IDs must be unique within their collection.

A role has `id` and `inherits`. The latter is a unique list of declared role IDs. The directed relation means “this role confers its listed parent roles.” Self-loops, indirect cycles and undeclared parents are rejected. Multiple inheritance is allowed. An assigned role remains an effective role itself.

A rule has exactly:

```text
id, effect, roles, actions, resourceKinds, conditions
```

`effect` is `allow` or `deny`. The role, action and kind selectors are nonempty unique lists of allowed names, or exactly `["*"]`. Mixing `*` with named selectors is invalid. Within one selector, entries are ORed. All three selectors and all conditions must match a rule.

Known actions: `read`, `write`, `submit`, `approve`. Resource kinds: `document`, `payment`. Rule declaration order has no semantic priority. `roles=["*"]` matches every valid subject, including a subject with no assigned roles.

## Predicates

A condition has `left`, `op`, and `right`. `left` is one allowed attribute path. `op` is `eq` or `neq`. `right` has exactly one field: either `attribute` for another allowed path, or `value` for a literal.

| Path | Type |
| --- | --- |
| `subject.id`, `subject.tenant` | String |
| `resource.id`, `resource.tenant`, `resource.ownerId` | String |
| `resource.kind`, `resource.classification` | String |
| `context.network` | String |
| `context.mfa` | Boolean |

Both operands must have the same type. Boolean true is distinct from the string `"true"`; wrong-type predicates are rejected when loading the policy. String literals are valid UTF-8 and at most 64 bytes. Comparison is exact: no case folding, numeric coercion, substring matching or Unicode normalization.

Each rule has 0–8 conditions. The list is an AND; an empty list evaluates true. There are no expression strings, dynamic evaluation, arbitrary property access, functions, regexes, or implicit missing-value semantics. Runtime requests require every attribute field; malformed requests fail before evaluation.

## Decision procedure

1. Expand direct subject roles to their transitive inherited closure.
2. Find every rule whose role selector, action selector, resource-kind selector and conditions all match.
3. If any matching rule is a deny, return `allowed=false, reason="explicit-deny"`.
4. Otherwise, if at least one matching allow exists, return `allowed=true, reason="allow-rule"`.
5. Otherwise return `allowed=false, reason="default-deny"`.

The result includes sorted matching allow IDs, sorted matching deny IDs, sorted effective roles, and the role path for each matching named role selector. A wildcard role match has an empty path list; it is an unconditional selector match, not evidence of a particular assigned role.

For explanation paths, minimize number of edges first, then choose the lexicographically smallest full sequence of role IDs. When several assigned roles reach the same ancestor, the same ordering applies. Explain output also evaluates every rule's selector booleans and all predicate values, even when a different selector has already failed. That diagnostic evaluation does not change authorization.

## Request domain

The domain has `version`, `users`, `actions`, `resources`, `contexts`, and `constraints`.

- Users have `id`, `tenant`, and a unique list of assigned declared `roles`; 1–16 users.
- Resources have `id`, `tenant`, `kind`, `classification`, and `ownerId`; 1–16 resources. Classification is public/internal/restricted. An owner must be a declared user in the resource's tenant.
- Actions are a unique nonempty subset of the four known actions.
- Contexts have `id`, `network` and Boolean `mfa`; network is corporate/public. Context IDs and network/MFA combinations must be unique, with 1–4 contexts.

The complete domain is the Cartesian product of these four lists. Maximum size is 4,096. No allow-rule prefilter, owner filter or tenant filter reduces enumeration. Thus “complete” means complete for these fixed input lists and attribute values, not all requests expressible by a larger world.

The public evaluator can validate a standalone request's structure and types, but authentication and authoritative attribution are outside its contract. The CLI selects requests only from the supplied validated domain. The audit compares all policies against the same domain file and records that file's hash.

## Independent audit constraints

Constraints do not participate in the decision procedure. They inspect the resulting decisions or role closures:

- When `isolateTenants=true`, an allowed request with unequal subject/resource tenant is an isolation violation.
- When `prohibitSelfApproval=true`, an allowed `approve` request where subject ID equals resource owner ID is a self-approval violation.
- Each configured `exclusiveRolePairs` tuple is a pair of distinct declared roles. A user whose effective closure contains both has a static separation-of-duty conflict. Pairs are normalized internally and duplicates are rejected.

All conditions are checked directly from request attributes or effective roles, independently of rule IDs. Removing a policy deny does not remove the audit predicate. There is no session-level role activation model; static conflict means possession of both effective roles, even if no current request gains access.

## Diff and witness semantics

Requests are enumerated by ascending subject ID, action name, resource ID and context ID. The four-field tuple defines ordering; the slash-delimited request ID is a display/lookup encoding of it.

Newly allowed means baseline false and candidate true. Newly denied means baseline true and candidate false. A reason change compares only the three reason categories. Effective-role, matched-rule and explanation-path changes remain visible in complete matrices even when outcome/reason are unchanged.

The matrix difference helper checks equal cardinality and ordered request IDs. The audit/CLI ensure a shared domain; the helper alone cannot authenticate that identical IDs were assigned identical attributes by an external caller.

The selected request witness is the first actual finding in the declared tuple order. It is not an optimization over policy edits or attack steps. The selected static witness is the first conflicting user in the fixture, which contains one exclusive pair. Every finding remains listed in the raw artifacts so witness selection does not hide alternatives.

## Parsing and bounds

Input JSON is UTF-8 without a BOM, bounded to 65,536 bytes. Formatting whitespace outside strings is accepted. After parsing, non-string whitespace is removed from the original text and the token sequence must equal `JSON.stringify(parsed)`. Duplicate object keys, noncanonical token escapes, alternate number spellings and ambiguous serialization are therefore rejected. Object field order is not fixed; unknown or missing fields are rejected by the schema.

Objects passed directly to library validation are also checked and copied. All graph, list, enum and predicate bounds apply. Cycles and unknown role references fail before closure computation. Evaluation failures return no authorization decision; callers must treat errors as rejected requests.

Snapshots and reports are not signed. Hashes identify the recorded inputs and code; they do not authenticate an organization, certify a policy or make a finite-domain result an unbounded security claim.
