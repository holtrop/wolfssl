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
This module provides a Rust wrapper for the wolfCrypt library's EdDSA Curve
25519 (Ed25519) functionality.

It leverages the `wolfssl-sys` crate for low-level FFI bindings, encapsulating
the raw C functions in a memory-safe and easy-to-use Rust API.
*/

use crate::wolfcrypt::random::RNG;
use std::mem::MaybeUninit;
use wolfssl_sys as ws;

/// The `Ed25519` struct manages the lifecycle of a wolfSSL `ed25519_key`
/// object.
///
/// It ensures proper initialization and deallocation.
///
/// An instance can be created with `generate()` or `new()`.
pub struct Ed25519 {
    ws_key: ws::ed25519_key,
}

impl Ed25519 {
    pub const ED25519: u8 = ws::Ed25519 as u8;
    pub const ED25519CTX: u8 = ws::Ed25519ctx as u8;
    pub const ED25519PH: u8 = ws::Ed25519ph as u8;

    /// Generate a new Ed25519 key.
    ///
    /// # Parameters
    ///
    /// * `rng`: `RNG` instance to use for random number generation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ed25519) containing the Ed25519 struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    pub fn generate(rng: &mut RNG) -> Result<Self, i32> {
        let mut ws_key: MaybeUninit<ws::ed25519_key> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_ed25519_init(ws_key.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let ws_key = unsafe { ws_key.assume_init() };
        let mut ed25519 = Ed25519 { ws_key };
        let rc = unsafe {
            ws::wc_ed25519_make_key(&mut rng.wc_rng,
                ws::ED25519_KEY_SIZE as i32, &mut ed25519.ws_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(ed25519)
    }

    /// Create and initialize a new Ed25519 instance.
    ///
    /// # Returns
    ///
    /// Returns either Ok(ed25519) containing the Ed25519 struct instance or
    /// Err(e) containing the wolfSSL library error code value.
    pub fn new() -> Result<Self, i32> {
        let mut ws_key: MaybeUninit<ws::ed25519_key> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_ed25519_init(ws_key.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let ws_key = unsafe { ws_key.assume_init() };
        let ed25519 = Ed25519 { ws_key };
        Ok(ed25519)
    }

    /// Generate the Ed25519 public key from the private key stored in the
    /// Ed25519 object.
    ///
    /// The public key is written to the pubkey output buffer.
    ///
    /// # Parameters
    ///
    /// * `pubkey`: Output buffer in which to store the public key.
    pub fn make_public(&mut self, pubkey: &mut [u8]) -> Result<(), i32> {
        let pubkey_size = pubkey.len() as u32;
        let rc = unsafe {
            ws::wc_ed25519_make_public(&mut self.ws_key,
                pubkey.as_mut_ptr(), pubkey_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Sign a message using Ed25519 key.
    ///
    /// # Parameters
    ///
    /// * `message`: Message to sign.
    /// * `signature`: Output buffer to hold signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// signature on success or Err(e) containing the wolfSSL library error
    /// code value.
    pub fn sign_msg(&mut self, message: &[u8], signature: &mut [u8]) -> Result<usize, i32> {
        let message_size = message.len() as u32;
        let mut signature_size = signature.len() as u32;
        let rc = unsafe {
            ws::wc_ed25519_sign_msg(message.as_ptr(), message_size,
                signature.as_mut_ptr(), &mut signature_size, &mut self.ws_key)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(signature_size as usize)
    }

    /// Sign a message with context using Ed25519 key.
    ///
    /// The context is part of the data signed.
    ///
    /// # Parameters
    ///
    /// * `message`: Message to sign.
    /// * `context`: Buffer containing context for which message is being signed.
    /// * `signature`: Output buffer to hold signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// signature on success or Err(e) containing the wolfSSL library error
    /// code value.
    pub fn sign_msg_ctx(&mut self, message: &[u8], context: &[u8], signature: &mut [u8]) -> Result<usize, i32> {
        let message_size = message.len() as u32;
        let context_size = context.len() as u8;
        let mut signature_size = signature.len() as u32;
        let rc = unsafe {
            ws::wc_ed25519ctx_sign_msg(message.as_ptr(), message_size,
                signature.as_mut_ptr(), &mut signature_size, &mut self.ws_key,
                context.as_ptr(), context_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(signature_size as usize)
    }

    /// Sign a message digest with context using Ed25519 key.
    ///
    /// The context is part of the data signed.
    /// The message is pre-hashed before signature calculation.
    ///
    /// # Parameters
    ///
    /// * `hash`: Message digest to sign.
    /// * `context`: Buffer containing context for which hash is being signed.
    /// * `signature`: Output buffer to hold signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// signature on success or Err(e) containing the wolfSSL library error
    /// code value.
    pub fn sign_hash_ctx(&mut self, hash: &[u8], context: &[u8], signature: &mut [u8]) -> Result<usize, i32> {
        let hash_size = hash.len() as u32;
        let context_size = context.len() as u8;
        let mut signature_size = signature.len() as u32;
        let rc = unsafe {
            ws::wc_ed25519ph_sign_msg(hash.as_ptr(), hash_size,
                signature.as_mut_ptr(), &mut signature_size, &mut self.ws_key,
                context.as_ptr(), context_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(signature_size as usize)
    }

    /// Sign input data with optional context using Ed25519 key.
    ///
    /// If provided, the context is part of the data signed.
    ///
    /// # Parameters
    ///
    /// * `din`: Data to sign.
    /// * `context`: Optional buffer containing context for which din is being signed.
    /// * `typ`: One of `Ed25519::ED25519`, `Ed25519::ED25519CTX`, or `Ed25519::ED25519PH`.
    /// * `signature`: Output buffer to hold signature.
    ///
    /// # Returns
    ///
    /// Returns either Ok(size) containing the number of bytes written to
    /// signature on success or Err(e) containing the wolfSSL library error
    /// code value.
    pub fn sign_msg_ex(&mut self, din: &[u8], context: Option<&[u8]>, typ: u8, signature: &mut [u8]) -> Result<usize, i32> {
        let din_size = din.len() as u32;
        let mut context_ptr: *const u8 = core::ptr::null();
        let mut context_size = 0u8;
        if let Some(context) = context {
            context_ptr = context.as_ptr();
            context_size = context.len() as u8;
        }
        let mut signature_size = signature.len() as u32;
        let rc = unsafe {
            ws::wc_ed25519_sign_msg_ex(din.as_ptr(), din_size,
                signature.as_mut_ptr(), &mut signature_size, &mut self.ws_key,
                typ, context_ptr, context_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(signature_size as usize)
    }
}

impl Drop for Ed25519 {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { ws::wc_ed25519_free(&mut self.ws_key); }
    }
}
