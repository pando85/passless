//! Secure memory management with selective mlock
//!
//! This module provides memory regions that are locked to prevent swapping.
//! Pre-allocated arenas are used to avoid multiple mlock/munlock syscalls.

use libc::{mlock, munlock};
use log::{debug, warn};
use std::ops::{Deref, DerefMut};

/// Lock a memory region to prevent swapping
///
/// # Safety
/// The pointer must be valid and aligned
unsafe fn lock_memory(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }

    // SAFETY: Caller ensures ptr is valid and aligned
    let result = unsafe { mlock(ptr as *const libc::c_void, len) };
    if result == 0 {
        debug!("Locked {} bytes at {:p}", len, ptr);
        true
    } else {
        let err = std::io::Error::last_os_error();
        warn!("Failed to lock {} bytes at {:p}: {}", len, ptr, err);
        // Don't fail - just warn. Memory locking is defense-in-depth.
        false
    }
}

/// Unlock a memory region
///
/// # Safety
/// The pointer must be valid and aligned
unsafe fn unlock_memory(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }

    // SAFETY: Caller ensures ptr is valid and aligned
    let result = unsafe { munlock(ptr as *const libc::c_void, len) };
    if result == 0 {
        debug!("Unlocked {} bytes at {:p}", len, ptr);
    } else {
        let err = std::io::Error::last_os_error();
        warn!("Failed to unlock {} bytes at {:p}: {}", len, ptr, err);
    }
}

/// A fixed-size buffer that is locked in memory (stack or heap)
///
/// Memory is locked on creation and unlocked on drop.
/// The buffer is zeroed before unlocking for security.
pub struct LockedBuffer<T: Copy, const N: usize> {
    inner: [T; N],
    locked: bool,
}

impl<T: Default + Copy, const N: usize> LockedBuffer<T, N> {
    /// Create a new buffer, optionally locked in memory
    ///
    /// # Arguments
    /// * `enable_locking` - If true, lock the buffer in memory. If false, skip locking.
    pub fn new(enable_locking: bool) -> Self {
        let mut buffer = Self {
            inner: [T::default(); N],
            locked: false,
        };
        if enable_locking {
            buffer.lock();
        }
        buffer
    }

    fn lock(&mut self) {
        let ptr = self.inner.as_ptr() as *const u8;
        let len = N * std::mem::size_of::<T>();
        self.locked = unsafe { lock_memory(ptr, len) };
        if !self.locked {
            warn!(
                "Failed to lock buffer ({} bytes). Credentials may be swapped to disk.",
                len
            );
        }
    }
}

impl<T: Copy, const N: usize> LockedBuffer<T, N> {
    fn unlock(&mut self) {
        if !self.locked {
            return;
        }

        let ptr = self.inner.as_ptr() as *const u8;
        let len = N * std::mem::size_of::<T>();
        unsafe { unlock_memory(ptr, len) };
        self.locked = false;
    }
}

impl<T: Default + Copy, const N: usize> Default for LockedBuffer<T, N> {
    fn default() -> Self {
        // Default to not locking (safer for general use)
        Self::new(false)
    }
}

impl<T: Copy, const N: usize> Deref for LockedBuffer<T, N> {
    type Target = [T; N];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Copy, const N: usize> DerefMut for LockedBuffer<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: Copy, const N: usize> Drop for LockedBuffer<T, N> {
    fn drop(&mut self) {
        // Zero the memory before unlocking
        // SAFETY: We're writing to our own buffer
        unsafe {
            let ptr = self.inner.as_mut_ptr() as *mut u8;
            let len = N * std::mem::size_of::<T>();
            std::ptr::write_bytes(ptr, 0, len);
        }

        self.unlock();
    }
}

/// A pre-allocated arena for storing credentials in locked memory
///
/// This avoids the overhead of multiple mlock/munlock calls by allocating
/// a fixed-size buffer upfront and locking it once.
///
/// Typical credential size: ~200 bytes (serialized)
/// With 10 slots: ~2 KB total locked memory
pub struct LockedCredentialArena<const SLOTS: usize, const SLOT_SIZE: usize> {
    // Flat buffer: SLOTS * SLOT_SIZE bytes
    buffer: Box<[u8]>,
    // Track which slots are occupied
    occupied: [bool; SLOTS],
    locked: bool,
}

impl<const SLOTS: usize, const SLOT_SIZE: usize> LockedCredentialArena<SLOTS, SLOT_SIZE> {
    /// Create a new arena with pre-allocated memory, optionally locked
    ///
    /// # Arguments
    /// * `enable_locking` - If true, lock the arena in memory. If false, skip locking.
    pub fn new(enable_locking: bool) -> Self {
        let total_size = SLOTS * SLOT_SIZE;
        if enable_locking {
            debug!(
                "Creating locked credential arena: {} slots × {} bytes = {} bytes total",
                SLOTS, SLOT_SIZE, total_size
            );
        } else {
            debug!(
                "Creating credential arena (unlocked): {} slots × {} bytes = {} bytes total",
                SLOTS, SLOT_SIZE, total_size
            );
        }

        // Allocate buffer
        let buffer = vec![0u8; total_size].into_boxed_slice();

        let mut arena = Self {
            buffer,
            occupied: [false; SLOTS],
            locked: false,
        };

        // Lock the entire buffer once if requested
        if enable_locking {
            arena.lock();
        }

        arena
    }

    fn lock(&mut self) {
        let ptr = self.buffer.as_ptr();
        let len = self.buffer.len();
        self.locked = unsafe { lock_memory(ptr, len) };
        if self.locked {
            debug!("Successfully locked credential arena ({} bytes)", len);
        } else {
            warn!(
                "Failed to lock credential arena ({} bytes). Credentials may be swapped to disk.\n\
                 Hint: increase DefaultLimitMEMLOCK at /etc/systemd/system.conf and /etc/systemd/user.conf level.\n\
                 Hint: grant CAP_IPC_LOCK to the binary with: 'sudo setcap cap_ipc_lock=+ep $(which passless)'",
                len
            );
        }
    }

    fn unlock(&mut self) {
        if !self.locked {
            return;
        }

        let ptr = self.buffer.as_ptr();
        let len = self.buffer.len();
        unsafe { unlock_memory(ptr, len) };
        self.locked = false;
        debug!("Unlocked credential arena");
    }

    /// Find a free slot and return its index
    fn find_free_slot(&self) -> Option<usize> {
        self.occupied.iter().position(|&occupied| !occupied)
    }

    /// Allocate space for a credential, returns (slot_index, mutable_slice)
    pub fn allocate(&mut self) -> Option<(usize, &mut [u8])> {
        let slot = self.find_free_slot()?;
        self.occupied[slot] = true;

        let start = slot * SLOT_SIZE;
        let end = start + SLOT_SIZE;
        Some((slot, &mut self.buffer[start..end]))
    }

    /// Free a slot by index
    pub fn free(&mut self, slot: usize) {
        if slot < SLOTS && self.occupied[slot] {
            // Zero the slot before marking as free
            let start = slot * SLOT_SIZE;
            let end = start + SLOT_SIZE;
            self.buffer[start..end].fill(0);
            self.occupied[slot] = false;
            debug!("Freed credential slot {}", slot);
        }
    }

    /// Get a slice for reading from a slot
    pub fn get_slot(&self, slot: usize) -> Option<&[u8]> {
        if slot < SLOTS && self.occupied[slot] {
            let start = slot * SLOT_SIZE;
            let end = start + SLOT_SIZE;
            Some(&self.buffer[start..end])
        } else {
            None
        }
    }

    /// Get a mutable slice for a slot
    pub fn get_slot_mut(&mut self, slot: usize) -> Option<&mut [u8]> {
        if slot < SLOTS && self.occupied[slot] {
            let start = slot * SLOT_SIZE;
            let end = start + SLOT_SIZE;
            Some(&mut self.buffer[start..end])
        } else {
            None
        }
    }

    /// Get number of occupied slots
    pub fn occupied_count(&self) -> usize {
        self.occupied.iter().filter(|&&o| o).count()
    }

    /// Get total capacity
    pub fn capacity(&self) -> usize {
        SLOTS
    }
}

impl<const SLOTS: usize, const SLOT_SIZE: usize> Default
    for LockedCredentialArena<SLOTS, SLOT_SIZE>
{
    fn default() -> Self {
        // Default to not locking (safer for general use)
        Self::new(false)
    }
}

impl<const SLOTS: usize, const SLOT_SIZE: usize> Drop for LockedCredentialArena<SLOTS, SLOT_SIZE> {
    fn drop(&mut self) {
        // Zero all memory before unlocking
        self.buffer.fill(0);
        self.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_buffer() {
        let mut buffer = LockedBuffer::<u8, 64>::new(true);
        buffer[0] = 42;
        assert_eq!(buffer[0], 42);
        // Drop will unlock and zero
    }

    #[test]
    fn test_locked_arena() {
        let mut arena = LockedCredentialArena::<10, 256>::new(true);
        assert_eq!(arena.capacity(), 10);
        assert_eq!(arena.occupied_count(), 0);

        // Allocate a slot
        let (slot, data) = arena.allocate().expect("Should allocate");
        assert_eq!(slot, 0);
        data[0] = 42;

        // Read back
        assert_eq!(arena.get_slot(slot).unwrap()[0], 42);

        // Free
        arena.free(slot);
        assert_eq!(arena.occupied_count(), 0);
    }

    #[test]
    fn test_arena_full() {
        let mut arena = LockedCredentialArena::<2, 64>::new(true);

        let (slot1, _) = arena.allocate().expect("First allocation");
        let (_slot2, _) = arena.allocate().expect("Second allocation");

        assert_eq!(arena.occupied_count(), 2);

        // Third allocation should fail
        assert!(arena.allocate().is_none());

        // Free one and allocate again
        arena.free(slot1);
        let (slot3, _) = arena.allocate().expect("After freeing");
        assert_eq!(slot3, slot1); // Should reuse the freed slot
    }
}
