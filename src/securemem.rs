//! Secure memory wiping
//!
//! Zeroing a buffer on the last use is tricky as compiler can optimise it away.
//!
//! The wipe here is done with volatile writes, which the compiler has to emit as written,
//! surrounded by compiler barriers so that no access to the secret is moved across the point where
//! it is supposed to be gone.

use core::sync::atomic::{Ordering, compiler_fence};

/// Overwrite the `N` bytes of input with zeroes, in a way that cannot be
/// elided by the optimizer.
pub fn zero_bytes<const N: usize>(to_zero: &mut [u8; N]) {
    // TODO remove this once we can guard at compile time against using this with N=0
    if N == 0 {
        return;
    }
    let ptr = to_zero.as_mut_ptr();

    // make sure all read/write before this are done.
    compiler_fence(Ordering::SeqCst);

    for i in 0..N {
        // the write is volatile, hence observable behavior: it *should* be emitted even
        // though the value written is never read back, and it should not be merged
        // into a `memset` call that could be optimized away.
        unsafe { core::ptr::write_volatile(ptr.add(i), 0) }
    }

    optimization_barrier(to_zero);

    // make sure all future read/write after done after all the volatile zeroing are done
    compiler_fence(Ordering::SeqCst);
}

/// Try to make `val` observed by opaque code, so the optimizer cannot remove the
/// writes that precede it.
fn optimization_barrier<const N: usize>(val: &[u8; N]) {
    // N > 0 by zero_bytes
    // TODO use core::cfg_select! once the minimum Rust version is 1.95.
    #[cfg(all(
        not(miri),
        any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "arm64ec",
            target_arch = "loongarch64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "s390x",
            target_arch = "x86",
            target_arch = "x86_64",
        )
    ))]
    {
        // the asm block contains only a comment, and basic compiler flags
        unsafe {
            core::arch::asm!(
                "# {}",
                in(reg) val.as_ptr(),
                options(readonly, preserves_flags, nostack),
            )
        }
    }

    #[cfg(not(all(
        not(miri),
        any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "arm64ec",
            target_arch = "loongarch64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "s390x",
            target_arch = "x86",
            target_arch = "x86_64",
        )
    )))]
    {
        core::hint::black_box(val);
        let _ = unsafe { core::ptr::read_volatile(val.as_ptr()) };
    }
}
