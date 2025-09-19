/*!
This crate provides a Rust wrapper for the wolfCrypt library's Advanced
Encryption Standard (AES) functionality.

It leverages the `wolfssl-sys` crate for low-level FFI bindings, encapsulating
the raw C functions in a memory-safe and easy-to-use Rust API.

The primary component is the `AES` struct, which manages the lifecycle of a
wolfSSL `Aes` object. It ensures proper initialization and deallocation.

# Examples

```rust
use wolfssl::wolfcrypt::aes::*;

fn main() {
    // Create an AES instance.
    let mut aes = AES::new().expect("Failed to create AES");

    // TODO
}
```
*/
use wolfssl_sys as ws;

use std::mem::{size_of, MaybeUninit};

enum CipherMode {
    CBC,
    CCM,
    CFB,
    CTR,
    CTS,
    EAX,
    ECB,
    GCM,
    OFB,
    XTS,
}

pub use CipherMode::*;

/// Interface to wolfCrypt Advanced Encryption Standard (AES) operations.
///
/// This struct wraps the wolfssl `Aes` type, providing a high-level API
/// for encrypting and decrypting blocks of data using various AES cipher modes.
/// The `Drop` implementation ensures that the underlying wolfSSL AES context
/// is correctly freed when the `AES` struct instance goes out of scope,
/// preventing memory leaks.
pub struct AES {
    ws_aes: ws::Aes,
    mode: CipherMode,
}

impl AES {
    /// Create and initialize a new `AES` instance.
    ///
    /// # Parameters
    ///
    /// * `mode`: AES cipher mode (e.g. GCM, CTR, etc.).
    /// * `key`: Encryption/decryption key.
    /// * `iv`: Initialization vector to use (optional).
    ///
    /// # Returns
    ///
    /// A Result which is Ok(AES) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new<KeyT, IvT>(mode: CipherMode, key: &[KeyT], iv: Option<&[IvT]>) -> Result<Self, i32> {
        let mut ws_aes: MaybeUninit<ws::AES> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_AesInit(ws_aes.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let ws_aes = unsafe { ws_aes.assume_init() };
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = (key.len() * size_of::<KeyT>()) as u32;
        let iv_ptr = match iv {
            Some(iv) => iv.as_ptr() as *const u8,
            None => std::ptr::null(),
        }
        let iv_size = match iv {
            Some(iv) => (iv.len() * size_of::<IvT>()) as u32,
            None => 0u32,
        }
        match mode {
            CBC => {
            }
            CCM => {
            }
            CFB => {
            }
            CTR => {
                unsafe { ws::wc_AesCtrSetKey(&mut ws_aes, key_ptr, key_size, iv_ptr, iv_size); }
            }
            CTS => {
            }
            EAX => {
            }
            ECB => {
            }
            GCM => {
            }
            OFB => {
            }
            XTS => {
            }
        }
        let aes = AES {
            ws_aes,
            mode,
        };
        Ok(aes)
    }
}

impl Drop for AES {
    /// Safely free the underlying wolfSSL AES context.
    ///
    /// This calls the `wc_AesFree` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the AES
    /// struct instance goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.aes); }
    }
}
