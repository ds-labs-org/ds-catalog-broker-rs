//! Round-trips the compiled wasm32 module through the alloc/evaluate/dealloc
//! ABI in a wasmi instance, which has a real 32-bit linear memory.
//!
//! The test builds the module itself with
//! `cargo build -p policy-engine --target wasm32-unknown-unknown --release`
//! and needs the `wasm32-unknown-unknown` rustup target installed.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use serde_json::{Value, json};
use wasmi::{
    Engine, Instance, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder, TypedFunc,
};

fn wasm_bytes() -> &'static [u8] {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES.get_or_init(|| {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let target_dir = manifest.join("../../target");
        let status = Command::new(cargo)
            .args([
                "build",
                "-p",
                "policy-engine",
                "--target",
                "wasm32-unknown-unknown",
                "--release",
                "--target-dir",
            ])
            .arg(&target_dir)
            .current_dir(&manifest)
            .status()
            .expect("failed to run cargo");
        assert!(
            status.success(),
            "wasm build failed; install the target with `rustup target add wasm32-unknown-unknown`"
        );
        std::fs::read(target_dir.join("wasm32-unknown-unknown/release/policy_engine.wasm"))
            .expect("policy_engine.wasm not found after build")
    })
}

struct Guest {
    store: Store<StoreLimits>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    dealloc: TypedFunc<(i32, i32), ()>,
    evaluate: TypedFunc<(i32, i32), i64>,
}

impl Guest {
    fn new() -> Self {
        Self::with_limits(StoreLimitsBuilder::new().build())
    }

    fn with_limits(limits: StoreLimits) -> Self {
        let engine = Engine::default();
        let module = Module::new(&engine, wasm_bytes()).expect("valid wasm module");
        let mut store = Store::new(&engine, limits);
        store.limiter(|limits| limits);
        let linker = <Linker<StoreLimits>>::new(&engine);
        let instance: Instance = linker
            .instantiate_and_start(&mut store, &module)
            .expect("module instantiates with no imports");
        let memory = instance
            .get_memory(&store, "memory")
            .expect("exports memory");
        let alloc = instance
            .get_typed_func(&store, "alloc")
            .expect("exports alloc");
        let dealloc = instance
            .get_typed_func(&store, "dealloc")
            .expect("exports dealloc");
        let evaluate = instance
            .get_typed_func(&store, "evaluate")
            .expect("exports evaluate");
        Guest {
            store,
            memory,
            alloc,
            dealloc,
            evaluate,
        }
    }

    /// Full host-side call sequence: alloc, write, evaluate, read, dealloc both buffers.
    fn call(&mut self, request: &[u8]) -> Value {
        let len = request.len() as i32;
        let req_ptr = self.alloc.call(&mut self.store, len).expect("alloc");
        self.memory
            .write(&mut self.store, req_ptr as usize, request)
            .expect("write request");
        let packed = self
            .evaluate
            .call(&mut self.store, (req_ptr, len))
            .expect("evaluate");
        let out_ptr = (packed >> 32) as i32;
        let out_len = (packed & 0xFFFF_FFFF) as i32;
        let mut out = vec![0u8; out_len as usize];
        self.memory
            .read(&self.store, out_ptr as usize, &mut out)
            .expect("read response");
        self.dealloc
            .call(&mut self.store, (req_ptr, len))
            .expect("dealloc request");
        self.dealloc
            .call(&mut self.store, (out_ptr, out_len))
            .expect("dealloc response");
        serde_json::from_slice(&out).expect("response is JSON")
    }
}

fn permit_de_policy() -> Value {
    json!({
        "id": "policy-1",
        "kind": "Offer",
        "permissions": [{"action": "use", "constraints": [
            {"left_operand": "nationality", "operator": "eq", "right_operand": "DE"}
        ]}]
    })
}

#[test]
fn matching_permission_allows_through_the_abi() {
    let mut guest = Guest::new();
    let request = json!({
        "dataset_id": "urn:uuid:d1",
        "policies": [permit_de_policy()],
        "claims": {"nationality": "DE"}
    });
    let response = guest.call(request.to_string().as_bytes());
    assert_eq!(response["dataset_id"], "urn:uuid:d1");
    assert_eq!(response["decision"], "Allow");
    assert_eq!(
        response["reason"],
        "permission[0] of policy 'policy-1' matched: nationality eq DE"
    );
}

#[test]
fn unmatched_permission_denies_through_the_abi() {
    let mut guest = Guest::new();
    let request = json!({
        "dataset_id": "urn:uuid:d1",
        "policies": [permit_de_policy()],
        "claims": {"nationality": "FR"}
    });
    let response = guest.call(request.to_string().as_bytes());
    assert_eq!(response["decision"], "Deny");
}

#[test]
fn matching_prohibition_overrides_a_matching_permission() {
    let mut guest = Guest::new();
    let request = json!({
        "dataset_id": "d",
        "policies": [{
            "permissions": [{"action": "use"}],
            "prohibitions": [{"action": "use", "constraints": [
                {"left_operand": "scope", "operator": "isAnyOf", "right_operand": "banned, other"}
            ]}]
        }],
        "claims": {"scope": ["read", "banned"]}
    });
    let response = guest.call(request.to_string().as_bytes());
    assert_eq!(response["decision"], "Deny");
}

#[test]
fn malformed_request_fails_closed_without_trapping() {
    let mut guest = Guest::new();
    let response = guest.call(b"{not json");
    assert_eq!(response["decision"], "Deny");
    assert_eq!(response["dataset_id"], "");
    assert!(
        response["reason"]
            .as_str()
            .unwrap()
            .contains("did not match the schema")
    );
}

#[test]
fn instance_is_reusable_and_buffers_can_be_freed_repeatedly() {
    let mut guest = Guest::new();
    let request = json!({"dataset_id": "d", "policies": [], "claims": {}}).to_string();
    for _ in 0..200 {
        assert_eq!(guest.call(request.as_bytes())["decision"], "Allow");
    }
}

#[test]
fn negative_alloc_length_is_clamped_not_a_huge_allocation() {
    let mut guest = Guest::new();
    let ptr = guest
        .alloc
        .call(&mut guest.store, -1)
        .expect("alloc(-1) does not trap");
    guest
        .dealloc
        .call(&mut guest.store, (ptr, -1))
        .expect("dealloc(ptr, -1) does not trap");
}

/// The host caps the guest's memory at 8 MiB, so a 64 MiB allocation cannot
/// be served. The guest must report that with a null pointer, not trap.
#[test]
fn unservable_alloc_returns_null_instead_of_trapping() {
    let mut guest = Guest::with_limits(
        StoreLimitsBuilder::new()
            .memory_size(8 * 1024 * 1024)
            .trap_on_grow_failure(false)
            .build(),
    );
    let ptr = guest
        .alloc
        .call(&mut guest.store, 64 * 1024 * 1024)
        .expect("alloc of an unservable size does not trap");
    assert_eq!(ptr, 0, "an allocation that cannot be served returns 0");
    // The instance still works afterwards.
    let request = json!({"dataset_id": "d", "policies": [], "claims": {}}).to_string();
    assert_eq!(guest.call(request.as_bytes())["decision"], "Allow");
}

#[test]
fn module_exports_exactly_the_documented_abi() {
    let engine = Engine::default();
    let module = Module::new(&engine, wasm_bytes()).unwrap();
    let mut names: Vec<_> = module.exports().map(|e| e.name().to_string()).collect();
    names.sort();
    for needed in ["alloc", "dealloc", "evaluate", "memory"] {
        assert!(
            names.iter().any(|n| n == needed),
            "missing export {needed}: {names:?}"
        );
    }
}
