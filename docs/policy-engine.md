# policy-engine

`crates/policy-engine` is a decision function over a harvested ODRL policy
and a caller's identity claims. It compiles to a `wasm32-unknown-unknown`
module and also builds as a normal Rust library. It is a prototype: no
other crate in this workspace depends on it.

It comes from the design in the dataspace study repository's case study
`docs/case-studies/2026-08-30-attribute-based-odrl-policy-enforcement.md`.
That study's 2026-09-05 update records that profiles, an error result,
duties and a configuration field were built later in the separate
`ds-odrl-engine-rs` repository. The broker's response filtering
(`crates/ds-catalog-broker-rs/src/odrl_filter.rs`) uses that engine. This
crate stays at the original scope, so read it as the portable-ABI
prototype and not as the broker's policy path.

## What it decides

`evaluate(&EvaluateRequest) -> EvaluateResponse` takes a dataset id, a list
of policies and a flat claims map. A claim is a string or a list of
strings. Constraints support three operators, matched against the claim
named by `left_operand`:

| Operator | Matches when |
|---|---|
| `eq` | the claim equals, or the list contains, `right_operand` |
| `neq` | the claim is present and does not equal or contain `right_operand` |
| `isAnyOf` | the claim equals or contains any entry of the comma-separated `right_operand` |

A missing claim never matches, `neq` included. An unknown operator never
matches. The constraints of one rule are ANDed.

Rules combine across every attached policy, in this order:

1. Deny if any prohibition matches.
2. Allow if no policy declares any permission.
3. Allow if any permission matches.
4. Deny.

The response carries `dataset_id`, `decision` (`Allow` or `Deny`) and a
`reason` string meant for people. The reason has no stable structure.

Request:

```json
{
  "dataset_id": "urn:uuid:example-dataset-1",
  "policies": [{
    "id": "policy-1",
    "kind": "Offer",
    "permissions": [{"action": "use", "constraints": [
      {"left_operand": "nationality", "operator": "eq", "right_operand": "DE"}
    ]}]
  }],
  "claims": {"nationality": "DE", "scope": ["read", "write"]}
}
```

Response:

```json
{
  "dataset_id": "urn:uuid:example-dataset-1",
  "decision": "Allow",
  "reason": "permission[0] of policy 'policy-1' matched: nationality eq DE"
}
```

The `Policy`, `Rule` and `Constraint` types copy the field names of the
`catalog-core` types. The crate does not depend on `catalog-core`, so its
dependency graph stays free of host-specific crates.

## Build the wasm module

```bash
rustup target add wasm32-unknown-unknown
cargo build -p policy-engine --target wasm32-unknown-unknown --release
# target/wasm32-unknown-unknown/release/policy_engine.wasm
```

The module has no imports. It exports `memory`, `alloc`, `dealloc` and
`evaluate`.

## ABI

```text
alloc(len: i32) -> i32
dealloc(ptr: i32, len: i32)
evaluate(req_ptr: i32, req_len: i32) -> i64
```

A host calls them in this order:

1. `alloc(n)` for the request JSON, then write the `n` UTF-8 bytes into
   `memory` at the returned pointer.
2. `evaluate(ptr, n)`. The return value is `(out_ptr << 32) | out_len`.
3. Read `out_len` bytes of response JSON at `out_ptr`.
4. `dealloc(ptr, n)` for the request and `dealloc(out_ptr, out_len)` for
   the response.

`dealloc` must receive the same length the buffer was allocated with. A
negative length is treated as 0. Request JSON that does not match the
schema does not trap: the response is `Deny`, with an empty `dataset_id`
and a reason starting `policy-engine: request JSON did not match the
schema`.

The three raw-pointer exports are compiled only for `wasm32`. They cast
pointers to `i32`, which truncates on a 64-bit host, so they cannot be
called as native Rust.

## Tests

```bash
cargo test -p policy-engine
```

- Unit tests in `src/lib.rs` cover the operators, claim shapes, the
  deny-overrides order and multiple policies on one dataset.
- `tests/wasm_abi.rs` builds the module with the command above, loads it
  into a `wasmi` instance, and runs the full alloc, evaluate, dealloc
  sequence. It also checks malformed input, repeated calls on one
  instance, negative lengths and the export list. The test needs the
  `wasm32-unknown-unknown` target installed and fails with an install hint
  when the build fails.

Not covered here: a JVM host. The case study describes a Chicory harness,
but this crate contains none.
