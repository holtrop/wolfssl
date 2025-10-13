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
This module provides a Rust wrapper for the wolfCrypt library's Diffie-Hellman
(DH) functionality.

It leverages the `wolfssl-sys` crate for low-level FFI bindings, encapsulating
the raw C functions in a memory-safe and easy-to-use Rust API.

The primary component is the `DH` struct, which manages the lifecycle of a
wolfSSL `DhKey` object. It ensures proper initialization and deallocation.
*/

use wolfssl_sys as ws;

use std::mem::{MaybeUninit};
use std::ptr::null;
use crate::wolfcrypt::random::RNG;

pub struct DH {
    wc_dhkey: ws::DhKey,
}

impl DH {
    pub const FFDHE_2048: i32 = ws::WC_FFDHE_2048 as i32;
    pub const FFDHE_3072: i32 = ws::WC_FFDHE_2048 as i32;
    pub const FFDHE_4096: i32 = ws::WC_FFDHE_2048 as i32;
    pub const FFDHE_6144: i32 = ws::WC_FFDHE_2048 as i32;
    pub const FFDHE_8192: i32 = ws::WC_FFDHE_2048 as i32;

    /// Compare given DH parameters to named parameter set.
    ///
    /// # Parameters
    ///
    /// * `name`: DH parameters name, one of DH::FFDHE_*.
    /// * `p`: DH `p` parameter value.
    /// * `g`: DH `g` parameter value.
    /// * `q`: DH `q` parameter value (optional).
    ///
    /// # Returns
    ///
    /// Returns whether the parameters match the named parameters.
    pub fn compare_named_key(name: i32, p: &[u8], g: &[u8], q: Option<&[u8]>) -> bool {
        let p_size = p.len() as u32;
        let g_size = g.len() as u32;
        let mut no_q = 1i32;
        let mut q_ptr: *const u8 = null();
        let mut q_size = 0u32;
        if let Some(q) = q {
            no_q = 0;
            q_ptr = q.as_ptr();
            q_size = q.len() as u32;
        }
        let rc = unsafe {
            ws::wc_DhCmpNamedKey(name, no_q,
                p.as_ptr(), p_size,
                g.as_ptr(), g_size,
                q_ptr, q_size)
        };
        rc != 0
    }

    /// Create a new DH context by generating parameters.
    ///
    /// # Parameters
    ///
    /// * `rng`: `RNG` struct instance to use for random number generation.
    /// * `modulus_size`: Modulus size in bits.
    ///
    /// # Returns
    ///
    /// Returns either Ok(dh) containing the DH struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn generate(rng: &mut RNG, modulus_size: i32) -> Result<Self, i32> {
        let mut wc_dhkey: MaybeUninit<ws::DhKey> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitDhKey(wc_dhkey.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_dhkey = unsafe { wc_dhkey.assume_init() };
        let mut dh = DH { wc_dhkey };
        let rc = unsafe {
            ws::wc_DhGenerateParams(&mut rng.wc_rng, modulus_size, &mut dh.wc_dhkey)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(dh)
    }

    /// Get minimum key size for DH named parameter set.
    ///
    /// # Parameters
    ///
    /// * `name`: DH parameters name, one of DH::FFDHE_*.
    ///
    /// # Returns
    ///
    /// Minimum key size for the DH named parameter set.
    pub fn get_min_key_size_for_named_parameters(name: i32) -> u32 {
        unsafe { ws::wc_DhGetNamedKeyMinSize(name) }
    }

    /// Get parameter sizes for a named parameter set.
    ///
    /// # Parameters
    ///
    /// * `name`: DH parameters name, one of DH::FFDHE_*.
    /// * `p_size`: Output parameter containing size of DH `p` parameter.
    /// * `g_size`: Output parameter containing size of DH `g` parameter.
    /// * `q_size`: Output parameter containing size of DH `q` parameter.
    pub fn get_named_parameter_sizes(name: i32, p_size: &mut u32, g_size: &mut u32, q_size: &mut u32) {
        unsafe {
            ws::wc_DhGetNamedKeyParamSize(name, p_size, g_size, q_size)
        };
    }

    /// Create a new DH context using the named parameter set.
    ///
    /// # Parameters
    ///
    /// * `name`: DH parameters name, one of DH::FFDHE_*.
    ///
    /// # Returns
    ///
    /// Returns either Ok(dh) containing the DH struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn new_named(name: i32) -> Result<Self, i32> {
        let mut wc_dhkey: MaybeUninit<ws::DhKey> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitDhKey(wc_dhkey.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_dhkey = unsafe { wc_dhkey.assume_init() };
        let mut dh = DH { wc_dhkey };
        let rc = unsafe { ws::wc_DhSetNamedKey(&mut dh.wc_dhkey, name) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(dh)
    }

    /// Create a new DH context using the given p and g parameters.
    ///
    /// # Parameters
    ///
    /// * `p`: DH 'p' parameter value.
    /// * `g`: DH 'g' parameter value.
    ///
    /// # Returns
    ///
    /// Returns either Ok(dh) containing the DH struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn new_from_pg(p: &[u8], g: &[u8]) -> Result<Self, i32> {
        let p_size = p.len() as u32;
        let g_size = g.len() as u32;
        let mut wc_dhkey: MaybeUninit<ws::DhKey> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitDhKey(wc_dhkey.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_dhkey = unsafe { wc_dhkey.assume_init() };
        let mut dh = DH { wc_dhkey };
        let rc = unsafe {
            ws::wc_DhSetKey(&mut dh.wc_dhkey, p.as_ptr(), p_size, g.as_ptr(), g_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(dh)
    }

    /// Create a new DH context using the given p, g, and q parameters.
    ///
    /// # Parameters
    ///
    /// * `p`: DH 'p' parameter value.
    /// * `g`: DH 'g' parameter value.
    /// * `q`: DH 'q' parameter value.
    ///
    /// # Returns
    ///
    /// Returns either Ok(dh) containing the DH struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn new_from_pgq(p: &[u8], g: &[u8], q: &[u8]) -> Result<Self, i32> {
        let p_size = p.len() as u32;
        let g_size = g.len() as u32;
        let q_size = q.len() as u32;
        let mut wc_dhkey: MaybeUninit<ws::DhKey> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitDhKey(wc_dhkey.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_dhkey = unsafe { wc_dhkey.assume_init() };
        let mut dh = DH { wc_dhkey };
        let rc = unsafe {
            ws::wc_DhSetKey_ex(&mut dh.wc_dhkey, p.as_ptr(), p_size, g.as_ptr(), g_size, q.as_ptr(), q_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(dh)
    }

    /// Create a new DH context using the given p, g, and q parameters.
    ///
    /// # Parameters
    ///
    /// * `p`: DH 'p' parameter value.
    /// * `g`: DH 'g' parameter value.
    /// * `q`: DH 'q' parameter value.
    /// * `trusted`: Whether to skip the prime check for `p` parameter and mark
    ///   the DH context as trusted.
    /// * `rng`: `RNG` instance to use for random number generation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(dh) containing the DH struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn new_from_pgq_with_check(p: &[u8], g: &[u8], q: &[u8], trusted: i32, rng: &mut RNG) -> Result<Self, i32> {
        let p_size = p.len() as u32;
        let g_size = g.len() as u32;
        let q_size = q.len() as u32;
        let mut wc_dhkey: MaybeUninit<ws::DhKey> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitDhKey(wc_dhkey.as_mut_ptr()) };
        if rc != 0 {
            return Err(rc);
        }
        let wc_dhkey = unsafe { wc_dhkey.assume_init() };
        let mut dh = DH { wc_dhkey };
        let rc = unsafe {
            ws::wc_DhSetCheckKey(&mut dh.wc_dhkey, p.as_ptr(), p_size, g.as_ptr(), g_size, q.as_ptr(), q_size, trusted, &mut rng.wc_rng)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(dh)
    }

    /// Export Diffie-Hellman context parameters.
    ///
    /// # Parameters
    ///
    /// * `p`: Buffer in which to store the DH `p` parameter value.
    /// * `p_size`: Output parameter holding number of bytes written to `p`.
    /// * `q`: Buffer in which to store the DH `q` parameter value.
    /// * `q_size`: Output parameter holding number of bytes written to `q`.
    /// * `g`: Buffer in which to store the DH `g` parameter value.
    /// * `g_size`: Output parameter holding number of bytes written to `g`.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    pub fn export_params_raw(&mut self,
            p: &mut [u8], p_size: &mut u32,
            q: &mut [u8], q_size: &mut u32,
            g: &mut [u8], g_size: &mut u32) -> Result<(), i32> {
        *p_size = p.len() as u32;
        *q_size = q.len() as u32;
        *g_size = g.len() as u32;
        let rc = unsafe {
            ws::wc_DhExportParamsRaw(&mut self.wc_dhkey,
                p.as_mut_ptr(), p_size,
                q.as_mut_ptr(), q_size,
                g.as_mut_ptr(), g_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Generate a public/private key pair for the given DH parameters.
    ///
    /// # Parameters
    ///
    /// * `rng`: `RNG` instance used for random number generation.
    /// * `private`: Buffer in which to store the generated private key.
    /// * `private_size`: Output parameter storing the private key size in bytes.
    /// * `public`: Buffer in which to store the generated public key.
    /// * `public_size`: Output parameter storing the public key size in bytes.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) or Err(e) containing the wolfSSL library error
    /// code value.
    pub fn generate_key_pair(&mut self, rng: &mut RNG,
            private: &mut [u8], private_size: &mut u32,
            public: &mut [u8], public_size: &mut u32) -> Result<(), i32> {
        *private_size = private.len() as u32;
        *public_size = public.len() as u32;
        let rc = unsafe {
            ws::wc_DhGenerateKeyPair(&mut self.wc_dhkey, &mut rng.wc_rng,
                private.as_mut_ptr(), private_size,
                public.as_mut_ptr(), public_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for DH {
    /// Safely free the underlying wolfSSL DhKey context.
    ///
    /// This calls the `wc_FreeDhKey()` wolfssl library function.
    ///
    /// The Rust Drop trait guarantees that this method is called when the
    /// DH struct instance goes out of scope, automatically cleaning up
    /// resources and preventing memory leaks.
    fn drop(&mut self) {
        unsafe { ws::wc_FreeDhKey(&mut self.wc_dhkey); }
    }
}
