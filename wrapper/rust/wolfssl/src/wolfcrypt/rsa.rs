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
    pub const HASH_TYPE_NONE       : u32 = ws::wc_HashType_WC_HASH_TYPE_NONE;
    pub const HASH_TYPE_MD2        : u32 = ws::wc_HashType_WC_HASH_TYPE_MD2;
    pub const HASH_TYPE_MD4        : u32 = ws::wc_HashType_WC_HASH_TYPE_MD4;
    pub const HASH_TYPE_MD5        : u32 = ws::wc_HashType_WC_HASH_TYPE_MD5;
    pub const HASH_TYPE_SHA        : u32 = ws::wc_HashType_WC_HASH_TYPE_SHA;
    pub const HASH_TYPE_SHA224     : u32 = ws::wc_HashType_WC_HASH_TYPE_SHA224;
    pub const HASH_TYPE_SHA256     : u32 = ws::wc_HashType_WC_HASH_TYPE_SHA256;
    pub const HASH_TYPE_SHA384     : u32 = ws::wc_HashType_WC_HASH_TYPE_SHA384;
    pub const HASH_TYPE_SHA512     : u32 = ws::wc_HashType_WC_HASH_TYPE_SHA512;
    pub const HASH_TYPE_MD5_SHA    : u32 = ws::wc_HashType_WC_HASH_TYPE_MD5_SHA;
    pub const HASH_TYPE_SHA3_224   : u32 = ws::wc_HashType_WC_HASH_TYPE_SHA3_224;
    pub const HASH_TYPE_SHA3_256   : u32 = ws::wc_HashType_WC_HASH_TYPE_SHA3_256;
    pub const HASH_TYPE_SHA3_384   : u32 = ws::wc_HashType_WC_HASH_TYPE_SHA3_384;
    pub const HASH_TYPE_SHA3_512   : u32 = ws::wc_HashType_WC_HASH_TYPE_SHA3_512;
    pub const HASH_TYPE_BLAKE2B    : u32 = ws::wc_HashType_WC_HASH_TYPE_BLAKE2B;
    pub const HASH_TYPE_BLAKE2S    : u32 = ws::wc_HashType_WC_HASH_TYPE_BLAKE2S;
    pub const HASH_TYPE_SHA512_224 : u32 = ws::wc_HashType_WC_HASH_TYPE_SHA512_224;
    pub const HASH_TYPE_SHA512_256 : u32 = ws::wc_HashType_WC_HASH_TYPE_SHA512_256;
    pub const HASH_TYPE_SHAKE128   : u32 = ws::wc_HashType_WC_HASH_TYPE_SHAKE128;
    pub const HASH_TYPE_SHAKE256   : u32 = ws::wc_HashType_WC_HASH_TYPE_SHAKE256;

    pub const MGF1NONE       : i32 = ws::WC_MGF1NONE as i32;
    pub const MGF1SHA1       : i32 = ws::WC_MGF1SHA1 as i32;
    pub const MGF1SHA224     : i32 = ws::WC_MGF1SHA224 as i32;
    pub const MGF1SHA256     : i32 = ws::WC_MGF1SHA256 as i32;
    pub const MGF1SHA384     : i32 = ws::WC_MGF1SHA384 as i32;
    pub const MGF1SHA512     : i32 = ws::WC_MGF1SHA512 as i32;
    pub const MGF1SHA512_224 : i32 = ws::WC_MGF1SHA512_224 as i32;
    pub const MGF1SHA512_256 : i32 = ws::WC_MGF1SHA512_256 as i32;

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
    pub fn generate(size: i32, e: i64, rng: &mut RNG) -> Result<Self, i32> {
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

    pub fn export_key(&mut self,
            e: &mut [u8], e_size: &mut u32,
            n: &mut [u8], n_size: &mut u32,
            d: &mut [u8], d_size: &mut u32,
            p: &mut [u8], p_size: &mut u32,
            q: &mut [u8], q_size: &mut u32) -> Result<(), i32> {
        let e_ptr = e.as_ptr() as *mut u8;
        *e_size = e.len() as u32;
        let n_ptr = n.as_ptr() as *mut u8;
        *n_size = n.len() as u32;
        let d_ptr = d.as_ptr() as *mut u8;
        *d_size = d.len() as u32;
        let p_ptr = p.as_ptr() as *mut u8;
        *p_size = p.len() as u32;
        let q_ptr = q.as_ptr() as *mut u8;
        *q_size = q.len() as u32;
        let rc = unsafe {
            ws::wc_RsaExportKey(&mut self.wc_rsakey, e_ptr, e_size,
                n_ptr, n_size, d_ptr, d_size, p_ptr, p_size, q_ptr, q_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn export_public_key(&mut self,
            e: &mut [u8], e_size: &mut u32,
            n: &mut [u8], n_size: &mut u32) -> Result<(), i32> {
        let e_ptr = e.as_ptr() as *mut u8;
        *e_size = e.len() as u32;
        let n_ptr = n.as_ptr() as *mut u8;
        *n_size = n.len() as u32;
        let rc = unsafe {
            ws::wc_RsaFlattenPublicKey(&mut self.wc_rsakey, e_ptr, e_size,
                n_ptr, n_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn get_encrypt_size(&self) -> Result<usize, i32> {
        let rc = unsafe { ws::wc_RsaEncryptSize(&self.wc_rsakey) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    pub fn check(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_CheckRsaKey(&mut self.wc_rsakey) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn public_encrypt(&mut self, din: &[u8], dout: &mut [u8], rng: &mut RNG) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_RsaPublicEncrypt(din_ptr, din_size, dout_ptr, dout_size,
                &mut self.wc_rsakey, &mut rng.wc_rng)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    pub fn private_decrypt(&mut self, din: &[u8], dout: &mut [u8]) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_RsaPrivateDecrypt(din_ptr, din_size, dout_ptr, dout_size,
                &mut self.wc_rsakey)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    pub fn pss_sign(&mut self, din: &[u8], dout: &mut [u8], hash_algo: u32, mgf: i32, rng: &mut RNG) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_RsaPSS_Sign(din_ptr, din_size, dout_ptr, dout_size,
                hash_algo, mgf, &mut self.wc_rsakey, &mut rng.wc_rng)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    pub fn pss_check_padding(&mut self, din: &[u8], sig: &mut [u8], hash_algo: u32) -> Result<(), i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let sig_ptr = sig.as_ptr() as *mut u8;
        let sig_size = sig.len() as u32;
        let rc = unsafe {
            ws::wc_RsaPSS_CheckPadding(din_ptr, din_size, sig_ptr, sig_size,
                hash_algo)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn pss_verify(&mut self, din: &[u8], dout: &mut [u8], hash_algo: u32, mgf: i32) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_RsaPSS_Verify(din_ptr, din_size, dout_ptr, dout_size,
                hash_algo, mgf, &mut self.wc_rsakey)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    pub fn pss_verify_check(&mut self, din: &[u8], dout: &mut [u8], digest: &[u8], hash_algo: u32, mgf: i32) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let digest_ptr = digest.as_ptr() as *const u8;
        let digest_size = digest.len() as u32;
        let rc = unsafe {
            ws::wc_RsaPSS_VerifyCheck(din_ptr, din_size, dout_ptr, dout_size,
                digest_ptr, digest_size, hash_algo, mgf, &mut self.wc_rsakey)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    pub fn rsa_direct(&mut self, din: &[u8], dout: &mut [u8], typ: i32, rng: &mut RNG) -> Result<usize, i32> {
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
        Ok(dout_size as usize)
    }

    pub fn set_rng(&mut self, rng: &mut RNG) -> Result<(), i32> {
        let rc = unsafe {
            ws::wc_RsaSetRNG(&mut self.wc_rsakey, &mut rng.wc_rng)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn ssl_sign(&mut self, din: &[u8], dout: &mut [u8], rng: &mut RNG) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_RsaSSL_Sign(din_ptr, din_size, dout_ptr, dout_size,
                &mut self.wc_rsakey, &mut rng.wc_rng)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
    }

    pub fn ssl_verify(&mut self, din: &[u8], dout: &mut [u8]) -> Result<usize, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let dout_ptr = dout.as_ptr() as *mut u8;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_RsaSSL_Verify(din_ptr, din_size, dout_ptr, dout_size,
                &mut self.wc_rsakey)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc as usize)
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
