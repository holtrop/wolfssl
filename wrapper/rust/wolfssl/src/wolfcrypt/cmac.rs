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
This module provides a Rust wrapper for the wolfCrypt library's Cipher-based
Message Authentication Code (CMAC) functionality.

It leverages the `wolfssl-sys` crate for low-level FFI bindings, encapsulating
the raw C functions in a memory-safe and easy-to-use Rust API.
*/

use std::mem::MaybeUninit;
use wolfssl_sys as ws;

pub struct CMAC {
    ws_cmac: ws::Cmac,
}
impl CMAC {
    /// Create a new CMAC object using the given key.
    ///
    /// # Parameters
    ///
    /// * `key`: Buffer containing the key to use for CMAC generation.
    ///
    /// # Returns
    ///
    /// Returns either Ok(cmac) containing the CMAC struct instance or Err(e)
    /// containing the wolfSSL library error code value.
    pub fn new(key: &[u8]) -> Result<Self, i32> {
        let key_size = key.len() as u32;
        let mut ws_cmac: MaybeUninit<ws::Cmac> = MaybeUninit::uninit();
        let typ = ws::CmacType_WC_CMAC_AES as i32;
        let rc = unsafe {
            ws::wc_InitCmac(ws_cmac.as_mut_ptr(), key.as_ptr(), key_size,
                typ, core::ptr::null_mut())
        };
        if rc != 0 {
            return Err(rc);
        }
        let ws_cmac = unsafe { ws_cmac.assume_init() };
        let cmac = CMAC { ws_cmac };
        Ok(cmac)
    }

    /// Add CMAC input data.
    ///
    /// # Parameters
    ///
    /// * `data`: CMAC input data
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn update(&mut self, data: &[u8]) -> Result<(), i32> {
        let data_size = data.len() as u32;
        let rc = unsafe {
            ws::wc_CmacUpdate(&mut self.ws_cmac, data.as_ptr(), data_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    /// Generate the final Cipher-based Message Authentication Code result.
    ///
    /// # Parameters
    ///
    /// * `dout`: Output buffer.
    ///
    /// # Returns
    ///
    /// Returns either Ok(()) on success or Err(e) containing the wolfSSL
    /// library error code value.
    pub fn finalize(&mut self, dout: &mut [u8]) -> Result<(), i32> {
        let mut dout_size = dout.len() as u32;
        let rc = unsafe {
            ws::wc_CmacFinalNoFree(&mut self.ws_cmac,
                dout.as_mut_ptr(), &mut dout_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
impl Drop for CMAC {
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { ws::wc_CmacFree(&mut self.ws_cmac); }
    }
}
