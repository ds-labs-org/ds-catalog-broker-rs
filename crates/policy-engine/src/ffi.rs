//! The WASM ABI built on top of [`crate::evaluate`] — see the design
//! doc's "WASM architecture" section for the ABI's justification and
//! host-invocation flow. Four exports:
//!
//! ```text
//! alloc(len: i32) -> i32
//! dealloc(ptr: i32, len: i32)
//! evaluate(req_ptr: i32, req_len: i32) -> i64
//! ```
//!
//! (plus the guest's linear memory, exported under the conventional name
//! `memory` by the `wasm32-unknown-unknown` toolchain by default — no
//! code in this file is needed to arrange that).
//!
//! This is the *only* module in this crate that touches raw pointers;
//! [`crate::evaluate`] itself has zero FFI/unsafe involvement. Every
//! `unsafe` block below carries a comment explaining exactly which
//! invariant the caller (the host runtime on the other side of the ABI)
//! is trusted to uphold.
//!
//! **The three raw-pointer exports below (`alloc`/`dealloc`/`evaluate`)
//! are compiled only for `target_arch = "wasm32"`.** This isn't just
//! tidiness: `ptr as i32` only round-trips losslessly through
//! `i32 as *mut u8` when pointers genuinely are 32 bits, which is true
//! inside a wasm32 linear address space and false on a 64-bit native
//! host — calling these functions directly as native Rust truncates a
//! real 64-bit address down to 32 bits and hands the wrong address back
//! to the allocator, which segfaults (confirmed directly: an earlier
//! version of this module's own native test that called `alloc` then
//! `dealloc` in-process crashed with SIGSEGV for exactly this reason,
//! which is why that test is gone and the pointer-touching exports are
//! now gated). The real proof that the ABI itself is sound lives in
//! `tests/wasm_abi.rs`, which calls these exports the only way they are
//! actually meant to be called: through a `wasmi` `Instance` executing
//! the compiled `wasm32-unknown-unknown` module inside its own
//! genuinely-32-bit linear memory. [`pack`] is plain arithmetic with no
//! pointer involved, so it stays compiled and unit-tested on every
//! target.

#[cfg(target_arch = "wasm32")]
use crate::{Decision, EvaluateRequest, EvaluateResponse};

/// Allocate `len` bytes inside this module's linear memory and return a
/// pointer to the start of that buffer, for the host to write request
/// JSON bytes into before calling [`evaluate`].
///
/// # Allocation invariant this ABI relies on
///
/// `Vec::with_capacity(len)` for a `u8` element records exactly `len` as
/// the `Vec`'s own capacity (`Vec::capacity()` returns precisely what was
/// requested, not whatever the global allocator may have rounded up to
/// internally) — this is the standard alloc/dealloc idiom used throughout
/// the wasm-plugin ecosystem (wasm-bindgen's `__wbindgen_malloc`,
/// Extism's PDK helpers) for exactly this reason. [`dealloc`] below
/// reconstructs the *same* `Vec<u8>` from `(ptr, len)` alone, which is
/// only sound because of this invariant — negative `len` is clamped to 0
/// so a hostile or buggy host can't turn a negative-to-usize cast into a
/// huge allocation request. A `len` the allocator cannot serve returns 0
/// and the instance stays usable.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: i32) -> i32 {
    let len = len.max(0) as usize;
    let mut buf: Vec<u8> = Vec::new();
    // A request the allocator cannot serve returns 0 instead of panicking,
    // which would trap the instance. The host must check for 0.
    if buf.try_reserve_exact(len).is_err() {
        return 0;
    }
    let ptr = buf.as_mut_ptr();
    // SAFETY (not memory-unsafety, but a leak-by-design): ownership of
    // this allocation is being handed across the FFI boundary to the
    // host. `forget` stops Rust from freeing it the instant `buf` goes
    // out of scope; the host now owns it until a matching `dealloc` call
    // frees it. No pointer is dereferenced here, so this call itself has
    // no memory-safety precondition on the caller.
    std::mem::forget(buf);
    ptr as i32
}

/// Free a buffer previously returned by [`alloc`], or the response buffer
/// [`evaluate`] allocated internally (its `out_ptr` unpacked from the
/// packed `i64` it returns).
///
/// # Safety
///
/// `ptr` must be a pointer previously returned by [`alloc`] (or the
/// `out_ptr` half of a prior [`evaluate`] call's packed return value)
/// that has not already been freed, and `len` must be exactly the `len`
/// that allocation was made with (`alloc`'s `len` argument, or
/// `evaluate`'s `out_len`). Both are established by [`alloc`]'s own
/// capacity-equals-`len` invariant. Passing a `ptr`/`len` pair that
/// doesn't correspond to such a live allocation is undefined behavior
/// (double free, or freeing memory this module never owned).
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dealloc(ptr: i32, len: i32) {
    if ptr == 0 {
        return;
    }
    let len = len.max(0) as usize;
    // SAFETY: per this function's own `# Safety` contract, the caller
    // guarantees `ptr`/`len` exactly describe a still-live allocation
    // made by `alloc` (or by `evaluate`'s internal response-buffer
    // allocation, which upholds the same capacity-equals-`len` invariant
    // via `shrink_to_fit` before leaking it below). Reconstructing a
    // `Vec<u8>` with length 0 and that same capacity and letting it drop
    // immediately is exactly how to give that allocation back to the
    // allocator without touching its (uninitialized, from Rust's point of
    // view) contents.
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, 0, len);
    }
}

/// Read `req_len` bytes of UTF-8 JSON at `req_ptr` (an [`EvaluateRequest`]
/// per the design doc's schema), evaluate it via [`crate::evaluate`],
/// write the UTF-8 JSON [`EvaluateResponse`] into a freshly allocated
/// buffer, and return `(out_ptr << 32) | (out_len & 0xFFFFFFFF)` — the
/// packed pointer+length the design doc's ABI specifies, needed because a
/// wasm MVP function can only return one primitive value.
///
/// Request JSON that fails to deserialize as [`EvaluateRequest`] does not
/// panic — a panic traps the whole wasm instance, which this ABI has no
/// recovery story for and would leave the host unable to distinguish "the
/// evaluated decision was Deny" from "the module crashed". Instead it
/// degrades to a `Deny` response with a diagnostic `reason` and an empty
/// `dataset_id` (unrecoverable from JSON that didn't parse). This
/// fail-closed-on-malformed-input behavior is this FFI layer's own
/// addition on top of the design doc, which specifies only the
/// well-formed-request schema — named here rather than silently assumed.
///
/// # Safety
///
/// The caller must guarantee `req_ptr..req_ptr+req_len` is a byte range
/// entirely within this module's exported `memory`, was fully written by
/// the host (typically right after a matching `alloc(req_len)` call), and
/// is not concurrently mutated for the duration of this call.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn evaluate(req_ptr: i32, req_len: i32) -> i64 {
    let req_len = req_len.max(0) as usize;
    // SAFETY: per this function's own `# Safety` contract, the caller
    // guarantees `req_ptr`/`req_len` describe a valid, host-written,
    // non-concurrently-mutated byte range inside this module's own linear
    // memory for the duration of this call - exactly what
    // `slice::from_raw_parts` requires of its caller.
    let req_bytes = unsafe { std::slice::from_raw_parts(req_ptr as *const u8, req_len) };

    let response = match serde_json::from_slice::<EvaluateRequest>(req_bytes) {
        Ok(request) => crate::evaluate(&request),
        Err(err) => EvaluateResponse {
            dataset_id: String::new(),
            decision: Decision::Deny,
            reason: format!("policy-engine: request JSON did not match the schema: {err}"),
        },
    };

    // `EvaluateResponse` is a plain struct of String/enum/String fields -
    // serializing it to JSON cannot fail, so the only way this expect()
    // could fire is a bug in this crate's own types, not bad input.
    let mut out_bytes = serde_json::to_vec(&response).expect("EvaluateResponse always serializes");
    // Matches alloc()'s own capacity-equals-length invariant: without
    // this, Vec::to_vec's capacity could exceed its length, and a later
    // dealloc(out_ptr, out_len) reconstructing Vec::from_raw_parts with
    // the wrong capacity would be unsound.
    out_bytes.shrink_to_fit();
    let out_len = out_bytes.len();
    let out_ptr = out_bytes.as_mut_ptr();
    // SAFETY (leak-by-design, as in `alloc`): ownership of this response
    // buffer is being handed back to the host via the packed pointer this
    // function returns. `forget` stops Rust from freeing it when
    // `out_bytes` goes out of scope; the host is now solely responsible
    // for freeing it with a matching `dealloc(out_ptr, out_len)` call.
    std::mem::forget(out_bytes);

    pack(out_ptr as i32, out_len as i32)
}

/// Pack a `(ptr, len)` pair into one `i64` per the design doc's ABI:
/// `ptr` in the high 32 bits, `len` in the low 32 bits. `len` is masked to
/// its low 32 bits before packing so that, were it ever negative (it
/// never legitimately is - it comes from a `usize` buffer length), sign
/// extension from the `i32 as i64` cast could not bleed into the `ptr`
/// half.
#[cfg(any(target_arch = "wasm32", test))]
fn pack(ptr: i32, len: i32) -> i64 {
    ((ptr as i64) << 32) | (len as i64 & 0xFFFF_FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_round_trips_through_the_documented_bit_layout() {
        let packed = pack(0x1234_5678, 0x0000_00ab);
        assert_eq!((packed >> 32) as i32, 0x1234_5678);
        assert_eq!((packed & 0xFFFF_FFFF) as i32, 0x0000_00ab);
    }

    // `alloc`/`dealloc`/`evaluate` are not unit-tested here: calling them
    // directly as native Rust functions is exactly the unsound thing this
    // file's module doc warns about (their `i32`-as-pointer casts are
    // only lossless inside a genuine wasm32 address space). The real
    // proof they work is `tests/wasm_abi.rs`, which calls them through an
    // actual `wasmi` `Instance`.
}
