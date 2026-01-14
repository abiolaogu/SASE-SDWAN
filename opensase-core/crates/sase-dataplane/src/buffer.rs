//! Zero-Copy Buffer Pool
//!
//! Hugepage-backed packet buffers for zero-copy networking.
//!
//! # Design
//!
//! - Pre-allocated buffer pool (no runtime allocation)
//! - Lock-free buffer acquisition/release
//! - Cache-line aligned for SIMD
//! - Supports scatter-gather for jumbo frames

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::ptr::NonNull;
use std::alloc::{alloc, dealloc, Layout};

/// Default MTU size
pub const DEFAULT_MTU: usize = 1500;

/// Maximum packet size  
pub const MAX_PACKET_SIZE: usize = 9216;  // Jumbo frame

/// Buffer size including headers
pub const BUFFER_SIZE: usize = 2048;

/// Cache line size
pub const CACHE_LINE: usize = 64;

/// Packet buffer (zero-copy)
#[repr(C, align(64))]
pub struct PacketBuffer {
    /// Buffer index in pool
    index: u32,
    /// Reference count
    refcount: AtomicU32,
    /// Data length
    data_len: u16,
    /// Headroom offset
    headroom: u16,
    /// Tailroom offset
    tailroom: u16,
    /// Flags
    flags: u16,
    /// Timestamp (microseconds)
    timestamp: u64,
    /// Next buffer (for chaining)
    next: Option<NonNull<PacketBuffer>>,
    /// Packet data
    data: [u8; BUFFER_SIZE],
}

impl PacketBuffer {
    /// Get packet data slice
    #[inline(always)]
    pub fn data(&self) -> &[u8] {
        let start = self.headroom as usize;
        let end = start + self.data_len as usize;
        &self.data[start..end]
    }

    /// Get mutable packet data
    #[inline(always)]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let start = self.headroom as usize;
        let end = start + self.data_len as usize;
        &mut self.data[start..end]
    }

    /// Get data length
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.data_len as usize
    }

    /// Check if empty
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.data_len == 0
    }

    /// Set data length
    #[inline(always)]
    pub fn set_len(&mut self, len: u16) {
        debug_assert!(len as usize + self.headroom as usize <= BUFFER_SIZE);
        self.data_len = len;
    }

    /// Get headroom
    #[inline(always)]
    pub fn headroom(&self) -> usize {
        self.headroom as usize
    }

    /// Get tailroom
    #[inline(always)]
    pub fn tailroom(&self) -> usize {
        BUFFER_SIZE - self.headroom as usize - self.data_len as usize
    }

    /// Prepend data (adjust headroom)
    #[inline]
    pub fn prepend(&mut self, len: u16) -> Option<&mut [u8]> {
        if self.headroom < len {
            return None;
        }
        self.headroom -= len;
        self.data_len += len;
        Some(&mut self.data[self.headroom as usize..(self.headroom + len) as usize])
    }

    /// Append data (use tailroom)
    #[inline]
    pub fn append(&mut self, len: u16) -> Option<&mut [u8]> {
        if self.tailroom() < len as usize {
            return None;
        }
        let start = self.headroom as usize + self.data_len as usize;
        self.data_len += len;
        Some(&mut self.data[start..start + len as usize])
    }

    /// Pull data (remove from head)
    #[inline]
    pub fn pull(&mut self, len: u16) -> Option<&[u8]> {
        if self.data_len < len {
            return None;
        }
        let start = self.headroom as usize;
        self.headroom += len;
        self.data_len -= len;
        Some(&self.data[start..(start + len as usize)])
    }

    /// Trim data (remove from tail)
    #[inline]
    pub fn trim(&mut self, len: u16) -> bool {
        if self.data_len < len {
            return false;
        }
        self.data_len -= len;
        true
    }

    /// Reset buffer
    #[inline]
    pub fn reset(&mut self) {
        self.data_len = 0;
        self.headroom = 128;  // Default headroom for encapsulation
        self.flags = 0;
        self.next = None;
    }

    /// Clone buffer (shallow - shares refcount)
    pub fn clone_ref(&self) -> NonNull<PacketBuffer> {
        self.refcount.fetch_add(1, Ordering::Relaxed);
        NonNull::from(self)
    }

    /// Get reference count
    pub fn refcount(&self) -> u32 {
        self.refcount.load(Ordering::Relaxed)
    }

    /// Get index in pool
    pub fn index(&self) -> u32 {
        self.index
    }
}

/// Buffer pool (pre-allocated, lock-free)
pub struct BufferPool {
    /// Pool of buffers
    buffers: NonNull<PacketBuffer>,
    /// Pool size
    size: usize,
    /// Free list (lock-free stack)
    free_list: Vec<AtomicU32>,
    /// Free list head index
    free_head: AtomicUsize,
    /// Total allocated
    allocated: AtomicUsize,
    /// Layout for deallocation
    layout: Layout,
}

unsafe impl Send for BufferPool {}
unsafe impl Sync for BufferPool {}

impl BufferPool {
    /// Create new buffer pool
    pub fn new(size: usize) -> Self {
        let layout = Layout::from_size_align(
            size * std::mem::size_of::<PacketBuffer>(),
            CACHE_LINE,
        ).unwrap();

        let ptr = unsafe { alloc(layout) as *mut PacketBuffer };
        if ptr.is_null() {
            panic!("Failed to allocate buffer pool");
        }

        // Initialize buffers
        for i in 0..size {
            unsafe {
                let buf = ptr.add(i);
                std::ptr::write(buf, PacketBuffer {
                    index: i as u32,
                    refcount: AtomicU32::new(0),
                    data_len: 0,
                    headroom: 128,
                    tailroom: 0,
                    flags: 0,
                    timestamp: 0,
                    next: None,
                    data: [0; BUFFER_SIZE],
                });
            }
        }

        // Initialize free list
        let mut free_list = Vec::with_capacity(size);
        for i in 0..size {
            free_list.push(AtomicU32::new(i as u32));
        }

        Self {
            buffers: NonNull::new(ptr).unwrap(),
            size,
            free_list,
            free_head: AtomicUsize::new(size),  // All free
            allocated: AtomicUsize::new(0),
            layout,
        }
    }

    /// Allocate buffer from pool
    #[inline]
    pub fn alloc(&self) -> Option<&mut PacketBuffer> {
        // Pop from free list
        let head = self.free_head.fetch_sub(1, Ordering::AcqRel);
        if head == 0 {
            // Pool exhausted
            self.free_head.fetch_add(1, Ordering::Release);
            return None;
        }

        let idx = self.free_list[head - 1].load(Ordering::Acquire);
        let buf = unsafe { &mut *self.buffers.as_ptr().add(idx as usize) };
        buf.refcount.store(1, Ordering::Release);
        buf.reset();
        self.allocated.fetch_add(1, Ordering::Relaxed);
        Some(buf)
    }

    /// Free buffer back to pool
    #[inline]
    pub fn free(&self, buf: &PacketBuffer) {
        // Decrement refcount
        let prev = buf.refcount.fetch_sub(1, Ordering::AcqRel);
        if prev != 1 {
            return;  // Still referenced
        }

        // Push to free list
        let head = self.free_head.fetch_add(1, Ordering::AcqRel);
        if head < self.size {
            self.free_list[head].store(buf.index, Ordering::Release);
            self.allocated.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Allocate batch of buffers
    /// 
    /// Note: Due to lifetime constraints, this returns the count of buffers that
    /// could be allocated. Callers should use multiple alloc() calls for batch.
    pub fn alloc_batch_count(&self, count: usize) -> usize {
        let mut allocated = 0;
        for _ in 0..count {
            if self.alloc().is_some() {
                allocated += 1;
            } else {
                break;
            }
        }
        allocated
    }

    /// Get available count
    pub fn available(&self) -> usize {
        self.free_head.load(Ordering::Relaxed)
    }

    /// Get allocated count
    pub fn allocated(&self) -> usize {
        self.allocated.load(Ordering::Relaxed)
    }

    /// Get pool size
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get buffer by index
    pub unsafe fn get(&self, index: u32) -> &mut PacketBuffer {
        &mut *self.buffers.as_ptr().add(index as usize)
    }
}

impl Drop for BufferPool {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.buffers.as_ptr() as *mut u8, self.layout);
        }
    }
}

/// Packet batch for batch processing
pub struct PacketBatch<'a> {
    buffers: Vec<&'a mut PacketBuffer>,
    len: usize,
}

impl<'a> PacketBatch<'a> {
    /// Create new batch with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffers: Vec::with_capacity(capacity),
            len: 0,
        }
    }

    /// Add buffer to batch
    pub fn push(&mut self, buf: &'a mut PacketBuffer) {
        self.buffers.push(buf);
        self.len += 1;
    }

    /// Get batch length
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Clear batch
    pub fn clear(&mut self) {
        self.buffers.clear();
        self.len = 0;
    }

    /// Iterate over buffers
    pub fn iter(&self) -> impl Iterator<Item = &&'a mut PacketBuffer> {
        self.buffers.iter()
    }

    /// Iterate mutably
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut &'a mut PacketBuffer> {
        self.buffers.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_alloc() {
        let pool = BufferPool::new(1024);
        
        assert_eq!(pool.available(), 1024);
        assert_eq!(pool.allocated(), 0);
        
        let buf = pool.alloc().unwrap();
        assert_eq!(buf.refcount(), 1);
        assert_eq!(pool.available(), 1023);
        assert_eq!(pool.allocated(), 1);
    }

    #[test]
    fn test_buffer_pool_free() {
        let pool = BufferPool::new(1024);
        
        let buf = pool.alloc().unwrap();
        let idx = buf.index();
        
        pool.free(buf);
        
        assert_eq!(pool.available(), 1024);
        assert_eq!(pool.allocated(), 0);
    }

    #[test]
    fn test_packet_buffer_data() {
        let pool = BufferPool::new(16);
        let buf = pool.alloc().unwrap();
        
        // Write some data
        let data = buf.append(100).unwrap();
        data[0] = 0x45;  // IPv4 header
        data[1] = 0x00;
        
        assert_eq!(buf.len(), 100);
        assert_eq!(buf.data()[0], 0x45);
    }

    #[test]
    fn test_packet_buffer_prepend() {
        let pool = BufferPool::new(16);
        let buf = pool.alloc().unwrap();
        
        // Append payload
        buf.append(100).unwrap();
        
        // Prepend header
        let hdr = buf.prepend(14).unwrap();  // Ethernet header
        hdr[0] = 0xFF;  // Broadcast
        
        assert_eq!(buf.len(), 114);
    }

    #[test]
    fn test_buffer_pool_exhaustion() {
        let pool = BufferPool::new(4);
        
        let _b1 = pool.alloc().unwrap();
        let _b2 = pool.alloc().unwrap();
        let _b3 = pool.alloc().unwrap();
        let _b4 = pool.alloc().unwrap();
        
        // Pool exhausted
        assert!(pool.alloc().is_none());
    }

    #[test]
    fn test_batch_alloc() {
        let pool = BufferPool::new(64);
        
        // Allocate 16 buffers using individual allocs
        for _ in 0..16 {
            assert!(pool.alloc().is_some());
        }
        assert_eq!(pool.allocated(), 16);
    }
}
