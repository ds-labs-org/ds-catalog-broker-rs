//! WASM ABI over [`crate::evaluate`]: alloc, dealloc, evaluate. Red-step
//! stubs; each body traps until the green commit.

/// Allocate `len` bytes in linear memory and return the pointer.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn alloc(_len: i32) -> i32 {
    todo!("alloc")
}

/// Free a buffer returned by [`alloc`] or [`evaluate`].
///
/// # Safety
///
/// `ptr`/`len` must describe a live allocation made by this module.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dealloc(_ptr: i32, _len: i32) {
    todo!("dealloc")
}

/// Evaluate the request JSON at `req_ptr..req_ptr+req_len`; returns the
/// packed response pointer and length.
///
/// # Safety
///
/// The range must lie inside this module's memory and be fully written.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn evaluate(_req_ptr: i32, _req_len: i32) -> i64 {
    todo!("evaluate")
}

/// Pack a `(ptr, len)` pair into one `i64`: `ptr` high, `len` low.
#[cfg(any(target_arch = "wasm32", test))]
fn pack(_ptr: i32, _len: i32) -> i64 {
    todo!("pack")
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
