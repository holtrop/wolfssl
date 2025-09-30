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

    /// Load a public and private RSA keypair from DER-encoded buffer.
    pub fn new_from_der(der: &[u8]) -> Result<Self, i32> {
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
            ws::wc_RsaPrivateKeyDecode(der_ptr, &mut idx, &mut wc_rsakey, der_size)
        };
        if rc != 0 {
            unsafe { ws::wc_FreeRsaKey(&mut wc_rsakey); }
            return Err(rc);
        }
        let rsa = RSA { wc_rsakey };
        Ok(rsa)
    }

    /// Load a public RSA key from DER-encoded buffer.
    pub fn new_public_from_der(der: &[u8]) -> Result<Self, i32> {
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
            ws::wc_RsaPublicKeyDecode(der_ptr, &mut idx, &mut wc_rsakey, der_size)
        };
        if rc != 0 {
            unsafe { ws::wc_FreeRsaKey(&mut wc_rsakey); }
            return Err(rc);
        }
        let rsa = RSA { wc_rsakey };
        Ok(rsa)
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

    pub fn check(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_CheckRsaKey(&mut self.wc_rsakey) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn public_encrypt(&mut self, din: &[u8], dout: &mut [u8], rng: &mut RNG) -> Result<(), i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_RsaPublicEncrypt(din_ptr, din_size, dout_ptr, dout_size,
                &mut self.wc_rsakey, &mut rng.wc_rng)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn private_decrypt(&mut self, din: &[u8], dout: &mut [u8]) -> Result<(), i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_RsaPrivateDecrypt(din_ptr, din_size, dout_ptr, dout_size,
                &mut self.wc_rsakey)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn rsa_direct(&mut self, din: &[u8], dout: &mut [u8], typ: i32, rng: &mut RNG) -> Result<u32, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let mut dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_RsaDirect(din_ptr, din_size, dout_ptr, &mut dout_size,
                &mut self.wc_rsakey, typ, &mut rng.wc_rng)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(dout_size)
    }

    pub fn ssl_sign(&mut self, din: &[u8], dout: &mut [u8], rng: &mut RNG) -> Result<(), i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_RsaSSL_Sign(din_ptr, din_size, dout_ptr, dout_size,
                &mut self.wc_rsakey, &mut rng.wc_rng)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
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
