/*!
This module provides a Rust wrapper for the wolfCrypt library's RSA support.

It leverages the `wolfssl-sys` crate for low-level FFI bindings, encapsulating
the raw C functions in a memory-safe and easy-to-use Rust API.

The primary component is the `RSA` struct, which manages the lifecycle of a
wolfSSL `RsaKey` object. It ensures proper initialization and deallocation.
*/
use wolfssl_sys as ws;

use std::mem::{MaybeUninit};
use std::ptr::{null_mut};
use crate::wolfcrypt::random::RNG;

pub struct RSA {
    wc_rsakey: ws::RsaKey,
}

impl RSA {
    /// Create a new uninitialized RSA instance.
    ///
    /// This instance will not be holding a valid key.
    pub fn new() -> Result<Self, i32> {
        let mut wc_rsakey: MaybeUninit<ws::RsaKey> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitRsaKey(wc_rsakey.as_mut_ptr(), null_mut()) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_rsakey = unsafe { wc_rsakey.assume_init() };
        let rsa = RSA { wc_rsakey };
        Ok(rsa)
    }

    fn new_from_der_internal(der: &[u8], private: bool) -> Result<Self, i32> {
        let mut wc_rsakey: MaybeUninit<ws::RsaKey> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitRsaKey(wc_rsakey.as_mut_ptr(), null_mut()) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_rsakey = unsafe { wc_rsakey.assume_init() };
        let der_ptr = der.as_ptr() as *const u8;
        let der_size = der.len() as u32;
        let mut idx: u32 = 0;
        let rc = unsafe {
            if private {
                ws::wc_RsaPrivateKeyDecode(der_ptr, &mut idx, &mut wc_rsakey, der_size)
            } else {
                ws::wc_RsaPublicKeyDecode(der_ptr, &mut idx, &mut wc_rsakey, der_size)
            }
        };
        if rc != 0 {
            unsafe { ws::wc_FreeRsaKey(&mut wc_rsakey); }
            return Err(rc);
        }
        let rsa = RSA { wc_rsakey };
        Ok(rsa)
    }

    /// Load a public and private RSA keypair from DER-encoded buffer.
    pub fn new_from_der(der: &[u8]) -> Result<Self, i32> {
        return RSA::new_from_der_internal(der, true);
    }

    /// Load a public RSA key from DER-encoded buffer.
    pub fn new_public_from_der(der: &[u8]) -> Result<Self, i32> {
        return RSA::new_from_der_internal(der, false);
    }

    /// Generate a new RSA key using the given size and exponent.
    ///
    /// This function generates a RSA private key of length size (in bits) and
    /// given exponent (e). It then returns the RSA structure instance so that
    /// it may be used for encryption or signing operations. A secure number to
    /// use for e is 65537. size is required to be greater than or equal to
    /// RSA_MIN_SIZE and less than or equal to RSA_MAX_SIZE. For this function
    /// to be available, the option WOLFSSL_KEY_GEN must be enabled at compile
    /// time. This can be accomplished with --enable-keygen if using
    /// `./configure`.
    pub fn generate(size: i32, e: i64, mut rng: RNG) -> Result<Self, i32> {
        let mut wc_rsakey: MaybeUninit<ws::RsaKey> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitRsaKey(wc_rsakey.as_mut_ptr(), null_mut()) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_rsakey = unsafe { wc_rsakey.assume_init() };
        let rc = unsafe {
            ws::wc_MakeRsaKey(&mut wc_rsakey, size, e, &mut rng.wc_rng)
        };
        if rc != 0 {
            unsafe { ws::wc_FreeRsaKey(&mut wc_rsakey); }
            return Err(rc);
        }
        let rsa = RSA { wc_rsakey };
        Ok(rsa)
    }
}

impl Drop for RSA {
    /// Safely free the underlying wolfSSL RSA context.
    ///
    /// This calls the `wc_FreeRsaKey` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the RSA
    /// struct goes out of scope, automatically cleaning up resources and
    /// preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_FreeRsaKey(&mut self.wc_rsakey); }
    }
}
