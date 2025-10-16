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
This module provides a Rust wrapper for the wolfCrypt library's Secure Hash
Algorithm (SHA) functionality.

It leverages the `wolfssl-sys` crate for low-level FFI bindings, encapsulating
the raw C functions in a memory-safe and easy-to-use Rust API.
*/

use wolfssl_sys as ws;

use std::mem::MaybeUninit;
use std::ptr::null_mut;

/// Context for SHA-1 computation.
pub struct SHA {
    wc_sha: ws::wc_Sha,
}

impl SHA {
    pub fn new() -> Result<Self, i32> {
        let mut wc_sha: MaybeUninit<ws::wc_Sha> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitSha(wc_sha.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha = unsafe { wc_sha.assume_init() };
        let sha = SHA { wc_sha };
        Ok(sha)
    }

    pub fn init(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_InitSha(&mut self.wc_sha) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_ShaUpdate(&mut self.wc_sha, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != (ws::WC_SHA_DIGEST_SIZE as usize) {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            ws::wc_ShaFinal(&mut self.wc_sha, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for SHA {
    /// Safely free the underlying wolfSSL SHA context.
    ///
    /// This calls the `wc_ShaFree` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the SHA
    /// struct goes out of scope, automatically cleaning up resources and
    /// preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_ShaFree(&mut self.wc_sha); }
    }
}

/// Context for SHA-224 (SHA-2) computation.
pub struct SHA224 {
    wc_sha224: ws::wc_Sha224,
}

impl SHA224 {
    pub fn new() -> Result<Self, i32> {
        let mut wc_sha224: MaybeUninit<ws::wc_Sha224> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitSha224(wc_sha224.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha224 = unsafe { wc_sha224.assume_init() };
        let sha224 = SHA224 { wc_sha224 };
        Ok(sha224)
    }

    pub fn init(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_InitSha224(&mut self.wc_sha224) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_Sha224Update(&mut self.wc_sha224, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != (ws::WC_SHA224_DIGEST_SIZE as usize) {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            ws::wc_Sha224Final(&mut self.wc_sha224, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for SHA224 {
    /// Safely free the underlying wolfSSL SHA224 context.
    ///
    /// This calls the `wc_Sha224Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA224 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_Sha224Free(&mut self.wc_sha224); }
    }
}

/// Context for SHA-256 (SHA-2) computation.
pub struct SHA256 {
    wc_sha256: ws::wc_Sha256,
}

impl SHA256 {
    pub fn new() -> Result<Self, i32> {
        let mut wc_sha256: MaybeUninit<ws::wc_Sha256> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitSha256(wc_sha256.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha256 = unsafe { wc_sha256.assume_init() };
        let sha256 = SHA256 { wc_sha256 };
        Ok(sha256)
    }

    pub fn init(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_InitSha256(&mut self.wc_sha256) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_Sha256Update(&mut self.wc_sha256, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != (ws::WC_SHA256_DIGEST_SIZE as usize) {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            ws::wc_Sha256Final(&mut self.wc_sha256, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for SHA256 {
    /// Safely free the underlying wolfSSL SHA256 context.
    ///
    /// This calls the `wc_Sha256Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA256 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_Sha256Free(&mut self.wc_sha256); }
    }
}

/// Context for SHA-384 (SHA-2) computation.
pub struct SHA384 {
    wc_sha384: ws::wc_Sha384,
}

impl SHA384 {
    pub fn new() -> Result<Self, i32> {
        let mut wc_sha384: MaybeUninit<ws::wc_Sha384> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitSha384(wc_sha384.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha384 = unsafe { wc_sha384.assume_init() };
        let sha384 = SHA384 { wc_sha384 };
        Ok(sha384)
    }

    pub fn init(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_InitSha384(&mut self.wc_sha384) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_Sha384Update(&mut self.wc_sha384, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != (ws::WC_SHA384_DIGEST_SIZE as usize) {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            ws::wc_Sha384Final(&mut self.wc_sha384, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for SHA384 {
    /// Safely free the underlying wolfSSL SHA384 context.
    ///
    /// This calls the `wc_Sha384Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA384 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_Sha384Free(&mut self.wc_sha384); }
    }
}

/// Context for SHA-512 (SHA-2) computation.
pub struct SHA512 {
    wc_sha512: ws::wc_Sha512,
}

impl SHA512 {
    pub fn new() -> Result<Self, i32> {
        let mut wc_sha512: MaybeUninit<ws::wc_Sha512> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitSha512(wc_sha512.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha512 = unsafe { wc_sha512.assume_init() };
        let sha512 = SHA512 { wc_sha512 };
        Ok(sha512)
    }

    pub fn init(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_InitSha512(&mut self.wc_sha512) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_Sha512Update(&mut self.wc_sha512, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != (ws::WC_SHA512_DIGEST_SIZE as usize) {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            ws::wc_Sha512Final(&mut self.wc_sha512, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for SHA512 {
    /// Safely free the underlying wolfSSL SHA512 context.
    ///
    /// This calls the `wc_Sha512Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA512 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_Sha512Free(&mut self.wc_sha512); }
    }
}

/// Context for SHA3-224 computation.
pub struct SHA3_224 {
    wc_sha3: ws::wc_Sha3,
}

impl SHA3_224 {
    pub fn new() -> Result<Self, i32> {
        let mut wc_sha3: MaybeUninit<ws::wc_Sha3> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitSha3_224(wc_sha3.as_mut_ptr(), null_mut(), ws::INVALID_DEVID) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha3 = unsafe { wc_sha3.assume_init() };
        let sha3_224 = SHA3_224 { wc_sha3 };
        Ok(sha3_224)
    }

    pub fn init(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_InitSha3_224(&mut self.wc_sha3, null_mut(), ws::INVALID_DEVID) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_Sha3_224_Update(&mut self.wc_sha3, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != (ws::WC_SHA224_DIGEST_SIZE as usize) {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            ws::wc_Sha3_224_Final(&mut self.wc_sha3, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for SHA3_224 {
    /// Safely free the underlying wolfSSL SHA3_224 context.
    ///
    /// This calls the `wc_Sha3_224_Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA3_224 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_Sha3_224_Free(&mut self.wc_sha3); }
    }
}

/// Context for SHA3-256 computation.
pub struct SHA3_256 {
    wc_sha3: ws::wc_Sha3,
}

impl SHA3_256 {
    pub fn new() -> Result<Self, i32> {
        let mut wc_sha3: MaybeUninit<ws::wc_Sha3> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitSha3_256(wc_sha3.as_mut_ptr(), null_mut(), ws::INVALID_DEVID) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha3 = unsafe { wc_sha3.assume_init() };
        let sha3_256 = SHA3_256 { wc_sha3 };
        Ok(sha3_256)
    }

    pub fn init(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_InitSha3_256(&mut self.wc_sha3, null_mut(), ws::INVALID_DEVID) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_Sha3_256_Update(&mut self.wc_sha3, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != (ws::WC_SHA256_DIGEST_SIZE as usize) {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            ws::wc_Sha3_256_Final(&mut self.wc_sha3, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for SHA3_256 {
    /// Safely free the underlying wolfSSL SHA3_256 context.
    ///
    /// This calls the `wc_Sha3_256_Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA3_256 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_Sha3_256_Free(&mut self.wc_sha3); }
    }
}

/// Context for SHA3-384 computation.
pub struct SHA3_384 {
    wc_sha3: ws::wc_Sha3,
}

impl SHA3_384 {
    pub fn new() -> Result<Self, i32> {
        let mut wc_sha3: MaybeUninit<ws::wc_Sha3> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitSha3_384(wc_sha3.as_mut_ptr(), null_mut(), ws::INVALID_DEVID) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha3 = unsafe { wc_sha3.assume_init() };
        let sha3_384 = SHA3_384 { wc_sha3 };
        Ok(sha3_384)
    }

    pub fn init(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_InitSha3_384(&mut self.wc_sha3, null_mut(), ws::INVALID_DEVID) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_Sha3_384_Update(&mut self.wc_sha3, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != (ws::WC_SHA384_DIGEST_SIZE as usize) {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            ws::wc_Sha3_384_Final(&mut self.wc_sha3, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for SHA3_384 {
    /// Safely free the underlying wolfSSL SHA3_384 context.
    ///
    /// This calls the `wc_Sha3_384_Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA3_384 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_Sha3_384_Free(&mut self.wc_sha3); }
    }
}

/// Context for SHA3-512 computation.
pub struct SHA3_512 {
    wc_sha3: ws::wc_Sha3,
}

impl SHA3_512 {
    pub fn new() -> Result<Self, i32> {
        let mut wc_sha3: MaybeUninit<ws::wc_Sha3> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitSha3_512(wc_sha3.as_mut_ptr(), null_mut(), ws::INVALID_DEVID) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_sha3 = unsafe { wc_sha3.assume_init() };
        let sha3_512 = SHA3_512 { wc_sha3 };
        Ok(sha3_512)
    }

    pub fn init(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_InitSha3_512(&mut self.wc_sha3, null_mut(), ws::INVALID_DEVID) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_Sha3_512_Update(&mut self.wc_sha3, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        if hash.len() != (ws::WC_SHA512_DIGEST_SIZE as usize) {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let rc = unsafe {
            ws::wc_Sha3_512_Final(&mut self.wc_sha3, hash.as_mut_ptr())
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for SHA3_512 {
    /// Safely free the underlying wolfSSL SHA3_512 context.
    ///
    /// This calls the `wc_Sha3_512_Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHA3_512 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_Sha3_512_Free(&mut self.wc_sha3); }
    }
}

/// Context for SHAKE128 (SHA-3) computation.
pub struct SHAKE128 {
    wc_shake: ws::wc_Shake,
}

impl SHAKE128 {
    pub fn new() -> Result<Self, i32> {
        let mut wc_shake: MaybeUninit<ws::wc_Shake> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitShake128(wc_shake.as_mut_ptr(), null_mut(), ws::INVALID_DEVID) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_shake = unsafe { wc_shake.assume_init() };
        let shake128 = SHAKE128 { wc_shake };
        Ok(shake128)
    }

    pub fn init(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_InitShake128(&mut self.wc_shake, null_mut(), ws::INVALID_DEVID) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_Shake128_Update(&mut self.wc_shake, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        let hash_size = hash.len() as u32;
        let rc = unsafe {
            ws::wc_Shake128_Final(&mut self.wc_shake, hash.as_mut_ptr(), hash_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn absorb(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_Shake128_Absorb(&mut self.wc_shake, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn squeeze_blocks(&mut self, dout: &mut [u8]) -> Result<(), i32> {
        let dout_size = dout.len() as u32;
        if dout_size % ws::WC_SHA3_128_BLOCK_SIZE != 0 {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let n_blocks = (dout_size / ws::WC_SHA3_128_BLOCK_SIZE) as u32;
        let rc = unsafe {
            ws::wc_Shake128_SqueezeBlocks(&mut self.wc_shake, dout.as_mut_ptr(), n_blocks)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for SHAKE128 {
    /// Safely free the underlying wolfSSL SHAKE128 context.
    ///
    /// This calls the `wc_Shake128_Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHAKE128 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_Shake128_Free(&mut self.wc_shake); }
    }
}

/// Context for SHAKE256 (SHA-3) computation.
pub struct SHAKE256 {
    wc_shake: ws::wc_Shake,
}

impl SHAKE256 {
    pub fn new() -> Result<Self, i32> {
        let mut wc_shake: MaybeUninit<ws::wc_Shake> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitShake256(wc_shake.as_mut_ptr(), null_mut(), ws::INVALID_DEVID) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_shake = unsafe { wc_shake.assume_init() };
        let shake256 = SHAKE256 { wc_shake };
        Ok(shake256)
    }

    pub fn init(&mut self) -> Result<(), i32> {
        let rc = unsafe { ws::wc_InitShake256(&mut self.wc_shake, null_mut(), ws::INVALID_DEVID) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_Shake256_Update(&mut self.wc_shake, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn finalize(&mut self, hash: &mut [u8]) -> Result<(), i32> {
        let hash_size = hash.len() as u32;
        let rc = unsafe {
            ws::wc_Shake256_Final(&mut self.wc_shake, hash.as_mut_ptr(), hash_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn absorb(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_Shake256_Absorb(&mut self.wc_shake, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn squeeze_blocks(&mut self, dout: &mut [u8]) -> Result<(), i32> {
        let dout_size = dout.len() as u32;
        if dout_size % ws::WC_SHA3_256_BLOCK_SIZE != 0 {
            return Err(ws::wolfCrypt_ErrorCodes_BUFFER_E);
        }
        let n_blocks = (dout_size / ws::WC_SHA3_256_BLOCK_SIZE) as u32;
        let rc = unsafe {
            ws::wc_Shake256_SqueezeBlocks(&mut self.wc_shake, dout.as_mut_ptr(), n_blocks)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for SHAKE256 {
    /// Safely free the underlying wolfSSL SHAKE256 context.
    ///
    /// This calls the `wc_Shake256_Free` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// SHAKE256 struct goes out of scope, automatically cleaning up resources
    /// and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_Shake256_Free(&mut self.wc_shake); }
    }
}
