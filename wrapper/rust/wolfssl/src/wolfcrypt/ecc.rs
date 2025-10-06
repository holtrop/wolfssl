/*!
This module provides a Rust wrapper for the wolfCrypt library's ECC
functionality.

It leverages the `wolfssl-sys` crate for low-level FFI bindings, encapsulating
the raw C functions in a memory-safe and easy-to-use Rust API.

The primary component is the `ECC` struct, which manages the lifecycle of a
wolfSSL `ecc_key` object. It ensures proper initialization and deallocation.
*/

use wolfssl_sys as ws;

use std::mem::{MaybeUninit};
use crate::wolfcrypt::random::RNG;

/// The `ECC` struct manages the lifecycle of a wolfSSL `ecc_key` object.
///
/// It ensures proper initialization and deallocation.
///
/// An instance can be created with `generate()`, `import_x963()`,
/// `import_x963_ex()`, `import_private_key()`, `import_private_key_ex()`,
/// `import_raw()`, or `import_raw_ex()`.
pub struct ECC {
    wc_ecc_key: ws::ecc_key,
}

impl ECC {
    pub const CURVE_INVALID: i32 = ws::ecc_curve_ids_ECC_CURVE_INVALID;
    pub const CURVE_DEF: i32 = ws::ecc_curve_ids_ECC_CURVE_DEF;
    pub const SECP192R1: i32 = ws::ecc_curve_ids_ECC_SECP192R1;
    pub const PRIME192V2: i32 = ws::ecc_curve_ids_ECC_PRIME192V2;
    pub const PRIME192V3: i32 = ws::ecc_curve_ids_ECC_PRIME192V3;
    pub const PRIME239V1: i32 = ws::ecc_curve_ids_ECC_PRIME239V1;
    pub const PRIME239V2: i32 = ws::ecc_curve_ids_ECC_PRIME239V2;
    pub const PRIME239V3: i32 = ws::ecc_curve_ids_ECC_PRIME239V3;
    pub const SECP256R1: i32 = ws::ecc_curve_ids_ECC_SECP256R1;
    pub const SECP112R1: i32 = ws::ecc_curve_ids_ECC_SECP112R1;
    pub const SECP112R2: i32 = ws::ecc_curve_ids_ECC_SECP112R2;
    pub const SECP128R1: i32 = ws::ecc_curve_ids_ECC_SECP128R1;
    pub const SECP128R2: i32 = ws::ecc_curve_ids_ECC_SECP128R2;
    pub const SECP160R1: i32 = ws::ecc_curve_ids_ECC_SECP160R1;
    pub const SECP160R2: i32 = ws::ecc_curve_ids_ECC_SECP160R2;
    pub const SECP224R1: i32 = ws::ecc_curve_ids_ECC_SECP224R1;
    pub const SECP384R1: i32 = ws::ecc_curve_ids_ECC_SECP384R1;
    pub const SECP521R1: i32 = ws::ecc_curve_ids_ECC_SECP521R1;
    pub const SECP160K1: i32 = ws::ecc_curve_ids_ECC_SECP160K1;
    pub const SECP192K1: i32 = ws::ecc_curve_ids_ECC_SECP192K1;
    pub const SECP224K1: i32 = ws::ecc_curve_ids_ECC_SECP224K1;
    pub const SECP256K1: i32 = ws::ecc_curve_ids_ECC_SECP256K1;
    pub const BRAINPOOLP160R1: i32 = ws::ecc_curve_ids_ECC_BRAINPOOLP160R1;
    pub const BRAINPOOLP192R1: i32 = ws::ecc_curve_ids_ECC_BRAINPOOLP192R1;
    pub const BRAINPOOLP224R1: i32 = ws::ecc_curve_ids_ECC_BRAINPOOLP224R1;
    pub const BRAINPOOLP256R1: i32 = ws::ecc_curve_ids_ECC_BRAINPOOLP256R1;
    pub const BRAINPOOLP320R1: i32 = ws::ecc_curve_ids_ECC_BRAINPOOLP320R1;
    pub const BRAINPOOLP384R1: i32 = ws::ecc_curve_ids_ECC_BRAINPOOLP384R1;
    pub const BRAINPOOLP512R1: i32 = ws::ecc_curve_ids_ECC_BRAINPOOLP512R1;
    pub const SM2P256V1: i32 = ws::ecc_curve_ids_ECC_SM2P256V1;
    pub const X25519: i32 = ws::ecc_curve_ids_ECC_X25519;
    pub const X448: i32 = ws::ecc_curve_ids_ECC_X448;
    pub const SAKKE_1: i32 = ws::ecc_curve_ids_ECC_SAKKE_1;
    pub const CURVE_CUSTOM: i32 = ws::ecc_curve_ids_ECC_CURVE_CUSTOM;
    pub const CURVE_MAX: i32 = ws::ecc_curve_ids_ECC_CURVE_MAX;

    /// Generate a new ECC key with the given size.
    ///
    /// # Parameters
    ///
    /// * `size`: Desired key length in bytes.
    /// * `rng`: Reference to a `RNG` struct to use for random number
    ///   generation while making the key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng).expect("Error with generate()");
    /// ecc.check().expect("Error with check()");
    /// ```
    pub fn generate(size: i32, rng: &mut RNG) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<ws::ecc_key> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_ecc_init(wc_ecc_key.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            ws::wc_ecc_make_key(&mut rng.wc_rng, size, &mut wc_ecc_key)
        };
        if rc != 0 {
            unsafe { ws::wc_ecc_free(&mut wc_ecc_key); }
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Generate a new ECC key with the given size and curve.
    ///
    /// # Parameters
    ///
    /// * `size`: Desired key length in bytes.
    /// * `rng`: Reference to a `RNG` struct to use for random number
    ///   generation while making the key.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let curve_id = ECC::SECP256R1;
    /// let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    /// let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id).expect("Error with generate()");
    /// ecc.check().expect("Error with check()");
    /// ```
    pub fn generate_ex(size: i32, rng: &mut RNG, curve_id: i32) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<ws::ecc_key> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_ecc_init(wc_ecc_key.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            ws::wc_ecc_make_key_ex(&mut rng.wc_rng, size, &mut wc_ecc_key, curve_id)
        };
        if rc != 0 {
            unsafe { ws::wc_ecc_free(&mut wc_ecc_key); }
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Get the curve size corresponding to the given curve ID.
    ///
    /// # Parameters
    ///
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the curve size or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let curve_id = ECC::SECP256R1;
    /// let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    /// let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id).expect("Error with generate()");
    /// ecc.check().expect("Error with check()");
    /// ```
    pub fn get_curve_size_from_id(curve_id: i32) -> Result<i32, i32> {
        let rc = unsafe { ws::wc_ecc_get_curve_size_from_id(curve_id) };
        if rc < 0 {
            return Err(rc);
        }
        Ok(rc)
    }

    /// Perform basic sanity checks on the ECC key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::random::RNG;
    /// use wolfssl::wolfcrypt::ecc::ECC;
    /// let mut rng = RNG::new().expect("Failed to create RNG");
    /// let mut ecc = ECC::generate(32, &mut rng).expect("Error with generate()");
    /// ecc.check().expect("Error with check()");
    /// ```
    pub fn check(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_ecc_check_key(&mut self.wc_ecc_key) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn export_x963(&mut self, dout: &mut [u8]) -> Result<usize, i32> {
        let dout_ptr = dout.as_ptr() as *mut u8;
        let mut out_len: u32 = dout.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_export_x963(&mut self.wc_ecc_key, dout_ptr, &mut out_len)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(out_len as usize)
    }

    pub fn export_x963_compressed(&mut self, dout: &mut [u8]) -> Result<usize, i32> {
        let dout_ptr = dout.as_ptr() as *mut u8;
        let mut out_len: u32 = dout.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_export_x963_ex(&mut self.wc_ecc_key, dout_ptr, &mut out_len, 1)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(out_len as usize)
    }

    /// Associates a `RNG` instance with this `ECC` instance.
    ///
    /// This is necessary when wolfSSL is built with the `ECC_TIMING_RESISTANT`
    /// build option enabled.
    ///
    /// # Parameters
    ///
    /// * `rng`: The `RNG` struct instance to associate with this `ECC`
    ///   instance. The `RNG` struct should not be moved in memory after
    ///   calling this method.
    ///
    /// # Returns
    ///
    /// Returns Ok(()) on success or Err(e) containing the wolfSSL library
    /// error code value.
    pub fn set_rng(&mut self, rng: &mut RNG) -> Result<(), i32> {
        let rc = unsafe {
            ws::wc_ecc_set_rng(&mut self.wc_ecc_key, &mut rng.wc_rng)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for ECC {
    /// Safely free the underlying wolfSSL ECC context.
    ///
    /// This calls the `wc_ecc_key_free()` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the ECC
    /// struct goes out of scope, automatically cleaning up resources and
    /// preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_ecc_free(&mut self.wc_ecc_key); }
    }
}
