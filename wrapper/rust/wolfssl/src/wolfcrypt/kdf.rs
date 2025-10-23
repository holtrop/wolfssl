/*
 * Copyright (C) 2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*!
This module provides a Rust wrapper for the wolfCrypt library's KDF
functionality.

It leverages the `wolfssl-sys` crate for low-level FFI bindings, encapsulating
the raw C functions in a memory-safe and easy-to-use Rust API.
*/

//use std::mem::MaybeUninit;
use crate::wolfcrypt::hmac::HMAC;
use wolfssl_sys as ws;

/// Key Derivation Function (KDF) functionality.
pub struct KDF {
}

impl KDF {
    pub const PRF_HASH_NONE: i32 = ws::wc_MACAlgorithm_no_mac as i32;
    pub const PRF_HASH_MD5: i32 = ws::wc_MACAlgorithm_md5_mac as i32;
    pub const PRF_HASH_SHA: i32 = ws::wc_MACAlgorithm_sha_mac as i32;
    pub const PRF_HASH_SHA224: i32 = ws::wc_MACAlgorithm_sha224_mac as i32;
    pub const PRF_HASH_SHA256: i32 = ws::wc_MACAlgorithm_sha256_mac as i32;
    pub const PRF_HASH_SHA384: i32 = ws::wc_MACAlgorithm_sha384_mac as i32;
    pub const PRF_HASH_SHA512: i32 = ws::wc_MACAlgorithm_sha512_mac as i32;
    pub const PRF_HASH_RMD: i32 = ws::wc_MACAlgorithm_rmd_mac as i32;
    pub const PRF_HASH_BLAKE2B: i32 = ws::wc_MACAlgorithm_blake2b_mac as i32;
    pub const PRF_HASH_SM3: i32 = ws::wc_MACAlgorithm_sm3_mac as i32;

    pub const TYPE_SHA256: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA256 as i32;
    pub const TYPE_SHA384: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA384 as i32;
    pub const TYPE_SHA512: i32 = ws::wc_HashType_WC_HASH_TYPE_SHA512 as i32;

    /// Pseudo Random Function for MD5, SHA-1, SHA-256, SHA-384, or SHA-512
    ///
    /// # Parameters
    ///
    /// * `secret`: Secret key.
    /// * `seed`: Seed.
    /// * `hash_type`: PRF Hash type, one of `KDF::PRF_HASH_*`.
    /// * `heap`: Heap hint.
    /// * `dev_id` Device ID to use with crypto callbacks or async hardware.
    ///   Set to INVALID_DEVID (-2) if not used.
    /// * `dout`: Output buffer.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::kdf::KDF;
    /// use wolfssl_sys as ws;
    /// let secret = [0x10u8, 0xbc, 0xb4, 0xa2, 0xe8, 0xdc, 0xf1, 0x9b, 0x4c,
    ///     0x51, 0x9c, 0xed, 0x31, 0x1b, 0x51, 0x57, 0x02, 0x3f,
    ///     0xa1, 0x7d, 0xfb, 0x0e, 0xf3, 0x4e, 0x8f, 0x6f, 0x71,
    ///     0xa3, 0x67, 0x76, 0x6b, 0xfa, 0x5d, 0x46, 0x4a, 0xe8,
    ///     0x61, 0x18, 0x81, 0xc4, 0x66, 0xcc, 0x6f, 0x09, 0x99,
    ///     0x9d, 0xfc, 0x47];
    /// let seed = [0x73u8, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x66, 0x69,
    ///     0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x0b, 0x46, 0xba,
    ///     0x56, 0xbf, 0x1f, 0x5d, 0x99, 0xff, 0xe9, 0xbb, 0x43,
    ///     0x01, 0xe7, 0xca, 0x2c, 0x00, 0xdf, 0x9a, 0x39, 0x6e,
    ///     0xcf, 0x6d, 0x15, 0x27, 0x4d, 0xf2, 0x93, 0x96, 0x4a,
    ///     0x91, 0xde, 0x5c, 0xc0, 0x47, 0x7c, 0xa8, 0xae, 0xcf,
    ///     0x5d, 0x93, 0x5f, 0x4c, 0x92, 0xcc, 0x98, 0x5b, 0x43];
    /// let mut out = [0u8; 12];
    /// KDF::prf(&secret, &seed, KDF::PRF_HASH_SHA384,
    ///     core::ptr::null_mut(), ws::INVALID_DEVID,
    ///     &mut out).expect("Error with prf()");
    /// ```
    pub fn prf(secret: &[u8], seed: &[u8], hash_type: i32, heap: *mut ::std::os::raw::c_void, dev_id: i32, dout: &mut [u8]) -> Result<(), i32> {
        let secret_size = secret.len() as u32;
        let seed_size = seed.len() as u32;
        let dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_PRF(dout.as_mut_ptr(), dout_size,
                secret.as_ptr(), secret_size,
                seed.as_ptr(), seed_size,
                hash_type, heap, dev_id)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Perform RFC 5869 HKDF-Extract operation for TLS v1.3 key derivation.
    ///
    /// # Parameters
    ///
    /// * `typ`: Hash type, one of `KDF::TYPE_*`.
    /// * `salt`: Optional Salt value.
    /// * `key`: Optional Initial Key Material (IKM).
    /// * `out`: Output buffer to store TLS1.3 HKDF-Extract result (generated
    ///   Pseudo-Random Key (PRK)). The size of this buffer must match
    ///   `HMAC::get_hmac_size_by_type(typ)`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::hmac::HMAC;
    /// use wolfssl::wolfcrypt::kdf::KDF;
    /// use wolfssl_sys as ws;
    /// let mut secret = [0u8; ws::WC_SHA256_DIGEST_SIZE as usize];
    /// KDF::tls13_hkdf_extract(HMAC::TYPE_SHA256, None, None, &mut secret).expect("Error with tls13_hkdf_extract()");
    /// ```
    pub fn tls13_hkdf_extract(typ: i32, salt: Option<&[u8]>, key: Option<&mut [u8]>, out: &mut [u8]) -> Result<(), i32> {
        let mut salt_ptr = core::ptr::null();
        let mut salt_size = 0u32;
        if let Some(salt) = salt {
            salt_ptr = salt.as_ptr();
            salt_size = salt.len() as u32;
        }
        let mut ikm_buf = [0u8; ws::WC_MAX_DIGEST_SIZE as usize];
        let mut ikm_ptr = ikm_buf.as_mut_ptr();
        let mut ikm_size = 0u32;
        if let Some(key) = key {
            if key.len() > 0 {
                ikm_ptr = key.as_mut_ptr();
                ikm_size = key.len() as u32;
            }
        }
        if out.len() != HMAC::get_hmac_size_by_type(typ)? {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            ws::wc_Tls13_HKDF_Extract(out.as_mut_ptr(), salt_ptr, salt_size,
                ikm_ptr, ikm_size, typ)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Perform RFC 5869 HKDF-Extract operation for TLS v1.3 key derivation.
    ///
    /// This utilizes HMAC to convert `key`, `label`, and `info` into a
    /// derived key which is written to `out`.
    ///
    /// # Parameters
    ///
    /// * `typ`: Hash type, one of `HMAC::TYPE_*`.
    /// * `key`: Key to use for KDF (typically output of `HKDF::extract()`).
    /// * `protocol`: Buffer containing TLS protocol.
    /// * `label`: Buffer containing label.
    /// * `info`: Buffer containing additional info.
    /// * `out`: Output buffer to store TLS1.3 HKDF-Expand result. The buffer can be
    ///   any size.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use wolfssl::wolfcrypt::hmac::HMAC;
    /// use wolfssl::wolfcrypt::kdf::KDF;
    /// use wolfssl_sys as ws;
    /// let hash_hello1 = [
    ///     0x63u8, 0x83, 0x58, 0xab, 0x36, 0xcd, 0x0c, 0xf3,
    ///     0x26, 0x07, 0xb5, 0x5f, 0x0b, 0x8b, 0x45, 0xd6,
    ///     0x7d, 0x5b, 0x42, 0xdc, 0xa8, 0xaa, 0x06, 0xfb,
    ///     0x20, 0xa5, 0xbb, 0x85, 0xdb, 0x54, 0xd8, 0x8b
    /// ];
    /// let client_early_traffic_secret = [
    ///     0x20u8, 0x18, 0x72, 0x7c, 0xde, 0x3a, 0x85, 0x17, 0x72, 0xdc, 0xd7, 0x72,
    ///     0xb0, 0xfc, 0x45, 0xd0, 0x62, 0xb9, 0xbb, 0x38, 0x69, 0x05, 0x7b, 0xb4,
    ///     0x5e, 0x58, 0x5d, 0xed, 0xcd, 0x0b, 0x96, 0xd3
    /// ];
    /// let mut secret = [0u8; ws::WC_SHA256_DIGEST_SIZE as usize];
    /// KDF::tls13_hkdf_extract(HMAC::TYPE_SHA256, None, None, &mut secret).expect("Error with tls13_hkdf_extract()");
    /// let protocol_label = b"tls13 ";
    /// let ce_traffic_label = b"c e traffic";
    /// let mut expand_out = [0u8; ws::WC_SHA256_DIGEST_SIZE as usize];
    /// KDF::tls13_hkdf_expand_label(HMAC::TYPE_SHA256, &secret,
    ///     protocol_label, ce_traffic_label,
    ///     &hash_hello1, &mut expand_out).expect("Error with tls13_hkdf_expand_label()");
    /// ```
    pub fn tls13_hkdf_expand_label(typ: i32, key: &[u8], protocol: &[u8], label: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), i32> {
        let key_size = key.len() as u32;
        let protocol_size = protocol.len() as u32;
        let label_size = label.len() as u32;
        let info_size = info.len() as u32;
        let out_size = out.len() as u32;
        let rc = unsafe {
            ws::wc_Tls13_HKDF_Expand_Label(out.as_mut_ptr(), out_size,
                key.as_ptr(), key_size, protocol.as_ptr(), protocol_size,
                label.as_ptr(), label_size, info.as_ptr(), info_size, typ)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Perform SSH KDF operation.
    ///
    /// # Parameters
    ///
    /// * `typ`: Hash type, one of `KDF::TYPE_*`.
    /// * `key_id`
    /// * `k`
    /// * `h`
    /// * `session_id`
    /// * `key`: Output buffer.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn ssh_kdf(typ: i32, key_id: u8, k: &[u8], h: &[u8], session_id: &[u8], key: &mut [u8]) -> Result<(), i32> {
        let key_size = key.len() as u32;
        let k_size = k.len() as u32;
        let h_size = h.len() as u32;
        let session_size = session_id.len() as u32;
        let rc = unsafe {
            ws::wc_SSH_KDF(typ as u8, key_id,
                key.as_mut_ptr(), key_size,
                k.as_ptr(), k_size, h.as_ptr(), h_size,
                session_id.as_ptr(), session_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
