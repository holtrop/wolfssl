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

/// Rust wrapper for wolfSSL `ecc_point` object.
pub struct ECCPoint {
    wc_ecc_point: ws::ecc_point,
}

impl ECCPoint {
    /// Import an ECCPoint from a DER-formatted buffer.
    ///
    /// # Parameters
    ///
    /// * `din`: DER-formatted buffer.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECCPoint) containing the ECCPoint struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    pub fn import_der(din: &[u8], curve_id: i32) -> Result<Self, i32> {
        let wc_ecc_point: MaybeUninit<ws::ecc_point> = MaybeUninit::uninit();
        let mut wc_ecc_point = unsafe { wc_ecc_point.assume_init() };
        let din_size = din.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_import_point_der(din.as_ptr(), din_size, curve_id,
                &mut wc_ecc_point)
        };
        if rc != 0 {
            return Err(rc);
        }
        let eccpoint = ECCPoint { wc_ecc_point };
        Ok(eccpoint)
    }

    /// Import an ECCPoint from a DER-formatted buffer.
    ///
    /// # Parameters
    ///
    /// * `din`: DER-formatted buffer.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    /// * `short_key_size`: if shortKeySize != 0 then key size is always
    ///   (din.len() - 1) / 2.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECCPoint) containing the ECCPoint struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    pub fn import_der_ex(din: &[u8], curve_id: i32, short_key_size: i32) -> Result<Self, i32> {
        let wc_ecc_point: MaybeUninit<ws::ecc_point> = MaybeUninit::uninit();
        let mut wc_ecc_point = unsafe { wc_ecc_point.assume_init() };
        let din_size = din.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_import_point_der_ex(din.as_ptr(), din_size, curve_id,
                &mut wc_ecc_point, short_key_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        let eccpoint = ECCPoint { wc_ecc_point };
        Ok(eccpoint)
    }

    /// Zeroize the ECCPoint.
    pub fn forcezero(&mut self) {
        unsafe { ws::wc_ecc_forcezero_point(&mut self.wc_ecc_point) };
    }
}

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

    /// Import a public/private ECC key pair from a buffer containing the raw
    /// private key and a second buffer containing the ANSI X9.63 formatted
    /// public key. This function handles both compressed and uncompressed
    /// keys as long as wolfSSL is built with the HAVE_COMP_KEY build option
    /// enabled.
    ///
    /// # Parameters
    ///
    /// * `priv_buf`: Buffer containing the raw private key.
    /// * `pub_buf`: Buffer containing the ANSI X9.63 formatted public key.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn import_private_key(priv_buf: &[u8], pub_buf: &[u8]) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<ws::ecc_key> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_ecc_init(wc_ecc_key.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let priv_size = priv_buf.len() as u32;
        let pub_size = pub_buf.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_import_private_key(priv_buf.as_ptr(), priv_size,
                pub_buf.as_ptr(), pub_size, &mut wc_ecc_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import a public/private ECC key pair from a buffer containing the raw
    /// private key and a second buffer containing the ANSI X9.63 formatted
    /// public key. This function handles both compressed and uncompressed
    /// keys as long as wolfSSL is built with the HAVE_COMP_KEY build option
    /// enabled. This function allows the curve ID to be explicitly specified.
    ///
    /// # Parameters
    ///
    /// * `priv_buf`: Buffer containing the raw private key.
    /// * `pub_buf`: Buffer containing the ANSI X9.63 formatted public key.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn import_private_key_ex(priv_buf: &[u8], pub_buf: &[u8], curve_id: i32) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<ws::ecc_key> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_ecc_init(wc_ecc_key.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let priv_size = priv_buf.len() as u32;
        let pub_size = pub_buf.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_import_private_key_ex(priv_buf.as_ptr(), priv_size,
                pub_buf.as_ptr(), pub_size, &mut wc_ecc_key, curve_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import raw ECC key from components in hexadecimal ASCII string format
    /// with curve name specified.
    ///
    /// # Parameters
    ///
    /// * `qx`: X component of public key as null terminated ASCII hex string.
    /// * `qy`: Y component of public key as null terminated ASCII hex string.
    /// * `d`: Private key as null terminated ASCII hex string.
    /// * `curve_name`: Null terminated ASCII string containing the curve name.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn import_raw(qx: &[i8], qy: &[i8], d: &[i8], curve_name: &[i8]) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<ws::ecc_key> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_ecc_init(wc_ecc_key.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            ws::wc_ecc_import_raw(&mut wc_ecc_key, qx.as_ptr(), qy.as_ptr(),
                d.as_ptr(), curve_name.as_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import raw ECC key from components in hexadecimal ASCII string format
    /// with curve ID specified.
    ///
    /// # Parameters
    ///
    /// * `qx`: X component of public key as null terminated ASCII hex string.
    /// * `qy`: Y component of public key as null terminated ASCII hex string.
    /// * `d`: Private key as null terminated ASCII hex string.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn import_raw_ex(qx: &[i8], qy: &[i8], d: &[i8], curve_id: i32) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<ws::ecc_key> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_ecc_init(wc_ecc_key.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            ws::wc_ecc_import_raw_ex(&mut wc_ecc_key, qx.as_ptr(), qy.as_ptr(),
                d.as_ptr(), curve_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import raw ECC key from components in binary unsigned integer format
    /// with curve ID specified.
    ///
    /// # Parameters
    ///
    /// * `qx`: X component of public key in binary unsigned integer format.
    /// * `qy`: Y component of public key in binary unsigned integer format.
    /// * `d`: Private key in binary unsigned integer format.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn import_unsigned(qx: &[u8], qy: &[u8], d: &[u8], curve_id: i32) -> Result<Self, i32> {
        let mut wc_ecc_key: MaybeUninit<ws::ecc_key> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_ecc_init(wc_ecc_key.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            ws::wc_ecc_import_unsigned(&mut wc_ecc_key, qx.as_ptr(), qy.as_ptr(),
                d.as_ptr(), curve_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import a public ECC key from the given buffer containing the key stored
    /// in ANSI X9.63 format. This function handles both compressed and
    /// uncompressed keys, as long as compressed keys are enabled at compile
    /// time with the HAVE_COMP_KEY build option.
    ///
    /// # Parameters
    ///
    /// * `din`: Buffer containing the ECC key encoded in ANSI X9.63 format.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn import_x963(din: &[u8]) -> Result<ECC, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let mut wc_ecc_key: MaybeUninit<ws::ecc_key> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_ecc_init(wc_ecc_key.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            ws::wc_ecc_import_x963(din_ptr, din_size, &mut wc_ecc_key)
        };
        if rc != 0 {
            unsafe { ws::wc_ecc_free(&mut wc_ecc_key); }
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
    }

    /// Import a public ECC key from the given buffer containing the key stored
    /// in ANSI X9.63 format. This function handles both compressed and
    /// uncompressed keys, as long as compressed keys are enabled at compile
    /// time with the HAVE_COMP_KEY build option.
    ///
    /// This function allows specifying the ECC curve ID to use.
    ///
    /// # Parameters
    ///
    /// * `din`: Buffer containing the ECC key encoded in ANSI X9.63 format.
    /// * `curve_id`: Curve ID, e.g. ECC::SECP256R1.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ECC) containing the ECC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn import_x963_ex(din: &[u8], curve_id: i32) -> Result<ECC, i32> {
        let din_ptr = din.as_ptr() as *const u8;
        let din_size = din.len() as u32;
        let mut wc_ecc_key: MaybeUninit<ws::ecc_key> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_ecc_init(wc_ecc_key.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let mut wc_ecc_key = unsafe { wc_ecc_key.assume_init() };
        let rc = unsafe {
            ws::wc_ecc_import_x963_ex(din_ptr, din_size, &mut wc_ecc_key, curve_id)
        };
        if rc != 0 {
            unsafe { ws::wc_ecc_free(&mut wc_ecc_key); }
            return Err(rc);
        }
        let ecc = ECC { wc_ecc_key };
        Ok(ecc)
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

    /// Export ECC key components in binary unsigned integer format.
    ///
    /// # Parameters
    ///
    /// * `qx`: Buffer in which to store public X component.
    /// * `qx_len`: Output parameter storing number of bytes written to `qx`.
    /// * `qy`: Buffer in which to store public Y component.
    /// * `qy_len`: Output parameter storing number of bytes written to `qy`.
    /// * `d`: Buffer in which to store private component.
    /// * `d_len`: Output parameter storing number of bytes written to `d`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    pub fn export(&mut self, qx: &mut [u8], qx_len: &mut u32,
            qy: &mut [u8], qy_len: &mut u32, d: &mut [u8], d_len: &mut u32) -> Result<(), i32> {
        *qx_len = qx.len() as u32;
        *qy_len = qy.len() as u32;
        *d_len = d.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_export_private_raw(&mut self.wc_ecc_key,
                qx.as_mut_ptr(), qx_len,
                qy.as_mut_ptr(), qy_len,
                d.as_mut_ptr(), d_len)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export ECC key components as either ASCII hexadecimal strings or
    /// in binary unsigned integer format.
    ///
    /// # Parameters
    ///
    /// * `qx`: Buffer in which to store public X component.
    /// * `qx_len`: Output parameter storing number of bytes written to `qx`.
    /// * `qy`: Buffer in which to store public Y component.
    /// * `qy_len`: Output parameter storing number of bytes written to `qy`.
    /// * `d`: Buffer in which to store private component.
    /// * `d_len`: Output parameter storing number of bytes written to `d`.
    /// * `hex`: true to output in ASCII hexadecimal string, false to output
    ///   as binary data.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    pub fn export_ex(&mut self, qx: &mut [u8], qx_len: &mut u32,
            qy: &mut [u8], qy_len: &mut u32, d: &mut [u8], d_len: &mut u32,
            hex: bool) -> Result<(), i32> {
        *qx_len = qx.len() as u32;
        *qy_len = qy.len() as u32;
        *d_len = d.len() as u32;
        let enc_type =
            if hex {
                ws::WC_TYPE_HEX_STR as i32
            } else {
                ws::WC_TYPE_UNSIGNED_BIN as i32
            };
        let rc = unsafe {
            ws::wc_ecc_export_ex(&mut self.wc_ecc_key,
                qx.as_mut_ptr(), qx_len,
                qy.as_mut_ptr(), qy_len,
                d.as_mut_ptr(), d_len,
                enc_type)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export private component from ECC key in binary unsigned integer form.
    ///
    /// # Parameters
    ///
    /// * `d`: Buffer in which to store private component.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to `d`
    /// or Err(e) containing the wolfSSL library error code value.
    pub fn export_private(&mut self, d: &mut [u8]) -> Result<usize, i32> {
        let mut d_size = d.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_export_private_only(&mut self.wc_ecc_key,
                d.as_mut_ptr(), &mut d_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(d_size as usize)
    }

    /// Export public ECC key components in binary unsigned integer format.
    ///
    /// # Parameters
    ///
    /// * `qx`: Buffer in which to store public X component.
    /// * `qx_len`: Output parameter storing number of bytes written to `qx`.
    /// * `qy`: Buffer in which to store public Y component.
    /// * `qy_len`: Output parameter storing number of bytes written to `qy`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    pub fn export_public(&mut self, qx: &mut [u8], qx_len: &mut u32,
            qy: &mut [u8], qy_len: &mut u32) -> Result<(), i32> {
        *qx_len = qx.len() as u32;
        *qy_len = qy.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_export_public_raw(&mut self.wc_ecc_key,
                qx.as_mut_ptr(), qx_len,
                qy.as_mut_ptr(), qy_len)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Export public key in ANSI X9.63 format.
    ///
    /// # Parameters
    ///
    /// * `dout`: Buffer to contain the output.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
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

    /// Export public key in ANSI X9.63 compressed format.
    ///
    /// # Parameters
    ///
    /// * `dout`: Buffer to contain the output.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
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

    /// Compute the ECDH shared secret using this key's private component
    /// and the peer public key.
    ///
    /// # Parameters
    ///
    /// * `peer`: `ECC` public key.
    /// * `dout`: Buffer in which to store the computed secret value.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    pub fn shared_secret(&mut self, peer_key: &mut ECC, dout: &mut [u8]) -> Result<usize, i32> {
        let mut out_len = dout.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_shared_secret(&mut self.wc_ecc_key,
                &mut peer_key.wc_ecc_key, dout.as_mut_ptr(), &mut out_len)
        };
        if rc < 0 {
            return Err(rc);
        }
        Ok(out_len as usize)
    }

    /// Compute the ECDH shared secret using this key's private component
    /// and the peer public point.
    ///
    /// # Parameters
    ///
    /// * `peer`: `ECCPoint` struct holding the public components of the peer
    ///   ECC key.
    /// * `dout`: Buffer in which to store the computed secret value.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    pub fn shared_secret_ex(&mut self, peer: &mut ECCPoint, dout: &mut [u8]) -> Result<usize, i32> {
        let mut out_len = dout.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_shared_secret_ex(&mut self.wc_ecc_key,
                &mut peer.wc_ecc_point, dout.as_mut_ptr(), &mut out_len)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(out_len as usize)
    }

    /// Sign a message digest using the ECC key.
    ///
    /// # Parameters
    ///
    /// * `din`: Message digest to sign.
    /// * `dout`: Buffer in which to store the signature.
    /// * `rng`: RNG struct to use for random number generation during signing.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// `dout` or Err(e) containing the wolfSSL library error code value.
    pub fn sign_hash(&mut self, din: &[u8], dout: &mut [u8], rng: &mut RNG) -> Result<usize, i32> {
        let din_size = din.len() as u32;
        let mut dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_sign_hash(din.as_ptr(), din_size, dout.as_mut_ptr(),
                &mut dout_size, &mut rng.wc_rng, &mut self.wc_ecc_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(dout_size as usize)
    }

    /// Verify the ECC signature of a hash.
    ///
    /// # Parameters
    ///
    /// * `sig`: ECC signature.
    /// * `hash`: Message digest.
    ///
    /// # Returns
    ///
    /// Returns either Ok(valid) containing a flag for whether the signature is
    /// valid or Err(e) containing the wolfSSL library error code value.
    pub fn verify_hash(&mut self, sig: &[u8], hash: &[u8]) -> Result<bool, i32> {
        let mut res: i32 = 0;
        let sig_len = sig.len() as u32;
        let hash_len = hash.len() as u32;
        let rc = unsafe {
            ws::wc_ecc_verify_hash(sig.as_ptr(), sig_len,
                hash.as_ptr(), hash_len, &mut res, &mut self.wc_ecc_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(res != 0)
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
