# Vendored dependencies

Three git submodules, each its own repo on the same Forgejo host as this
project, all owned by the `contreforts` org (a separate, private,
different-domain project: internal business-ops/ERP knowledge-graph
tooling, not dataspaces):

- `contreforts-kg` — an Oxigraph wrapper (`GraphStore`, `QueryEngine`).
  This is `rdf-store`'s real backend (`oxigraph_backend::OxigraphCatalogCache`,
  see that crate's module docs).
- `contreforts-core` — `contreforts-kg`'s own hard dependency: shared
  error types, a `ContrefortsConnector` trait, config helpers.
- `contreforts-config` — `contreforts-kg`'s other hard dependency: a
  second, separate Oxigraph store used for connector configuration.

`contreforts-kg` also depends on a fourth crate,
`contreforts-declaration` (a SHACL-based schema/lint engine), but that one
is nested *inside* `contreforts-core`'s own repo at
`contreforts-core/declaration` rather than being its own submodule, and
its `Cargo.toml` is fully self-contained (no `{ workspace = true }`
fields at all) - so it needed no vendoring decision of its own, just a
workspace-member entry pointing at that path.

## Why real workspace members, not a separate vendored workspace

The straightforward-looking alternative — vendor the whole `contreforts-workspace`
superproject as one submodule, and exclude it from this repo's own
`[workspace]` so it resolves its own `{ workspace = true }` fields against
its own root manifest — was tried first and works mechanically, but has
two real downsides this repo doesn't want:

1. It pulls in all 17 of that superproject's submodules (ERPNext/Pennylane/
   GitLab/O365/CalDAV/Stalwart/Forgejo connectors, a vector DB, a RAG
   engine, a config web UI, ...), none of which `contreforts-kg` actually
   depends on - Cargo loads a workspace's entire declared member list
   when resolving anything that belongs to it, so there's no way to fetch
   just the three crates actually needed while still deferring to that
   workspace's own root manifest.
2. `contreforts-workspace`'s own `[workspace.dependencies]` entry for
   `oxigraph` doesn't disable RocksDB's default feature, and this repo
   has no way to override that from outside - so `contreforts-config`
   (which depends on `oxigraph` unconditionally, with no feature switch of
   its own) would always pull in `oxrocksdb-sys`/`cmake`, regardless of
   anything done here.

Making `contreforts-kg`, `contreforts-core`, and `contreforts-config`
real members of *this* workspace instead means this repo's own root
`Cargo.toml` — not `contreforts-workspace`'s — owns `[workspace.dependencies]`
for all of them, including `oxigraph`'s `default-features = false`. That
is what actually makes a true in-memory-only build possible (see the root
`Cargo.toml`'s comment on that entry) — something the separate-workspace
approach could not achieve regardless of `contreforts-kg`'s own
[`contreforts/contreforts-kg#58`](https://labs.deepthought-solutions.net/contreforts/contreforts-kg/pulls/58)
feature switch, since `contreforts-config` has no matching switch of its
own.

## Known metadata caveat

`contreforts-core` and `contreforts-config`'s own (unvendored) `Cargo.toml`
files declare `edition.workspace = true` (and, for `contreforts-config`,
`license.workspace = true` / `authors.workspace = true`) expecting to
inherit from *their own* superproject's `[workspace.package]` — real
values `edition = "2024"`, `license = "MIT"`,
`authors = ["Deepthought Solutions"]`. Making them members of this
workspace instead means they inherit **this** repo's `[workspace.package]`
values. `edition` and `authors` were matched deliberately (see the root
`Cargo.toml`'s comments) so nothing actually changes for them. So was
`license`: the root `[workspace.package]` declares `license = "MIT"` only
for `contreforts-config`'s benefit, while this project's own crates
(`crates/*`, GPL-3.0-or-later) set their `license` field directly instead
of inheriting it. `contreforts-core` and `contreforts-kg` declare no
`license` field at all in their vendored `Cargo.toml`, so `cargo metadata`
reports none for them; their real, upstream license is MIT. Cargo has no
per-member override for a `{ workspace = true }` field short of editing
the vendored `Cargo.toml` itself, which isn't something this repo should
do to someone else's upstream file.

## Pin status

- `contreforts-core`, `contreforts-config`: pinned to their `develop` tip
  at the time each was vendored.
- `contreforts-kg`: pinned to commit `7cce680c23a8d344df26210011b97f793f26dd3a`,
  the tip of an **open, not-yet-merged** pull request,
  [`contreforts/contreforts-kg#58`](https://labs.deepthought-solutions.net/contreforts/contreforts-kg/pulls/58)
  ("add rocksdb feature switch for in-memory-only Oxigraph builds") — not
  a normal `develop` commit. This is deliberate and temporary: the
  feature this project's Oxigraph backend is built against didn't exist
  on `develop` yet. Once #58 merges, re-pin with:

  ```bash
  cd vendor/contreforts-kg
  git checkout develop && git pull --ff-only
  cd ../..
  git add vendor/contreforts-kg
  git commit -m "Re-pin contreforts-kg to develop now that contreforts-kg#58 merged"
  ```
