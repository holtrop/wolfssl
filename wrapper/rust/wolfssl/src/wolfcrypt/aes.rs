/*!
This crate provides a Rust wrapper for the wolfCrypt library's Advanced
Encryption Standard (AES) functionality.

It leverages the `wolfssl-sys` crate for low-level FFI bindings, encapsulating
the raw C functions in a memory-safe and easy-to-use Rust API.
*/

use std::mem::{size_of, MaybeUninit};
use std::ptr::{null, null_mut};
use wolfssl_sys as ws;

pub struct CBC {
    ws_aes: ws::Aes,
}
impl CBC {
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let cbc = CBC {ws_aes};
        Ok(cbc)
    }

    fn init(&mut self, key: &[u8], iv: &[u8], dir: i32) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        if iv.len() as u32 != ws::WC_AES_BLOCK_SIZE {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesSetKey(&mut self.ws_aes, key_ptr, key_size,
                iv_ptr, dir)
        };
        if rc != 0 {
            Err(rc)
        } else {
            Ok(())
        }
    }

    pub fn init_encrypt(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        return self.init(key, iv, ws::AES_ENCRYPTION as i32);
    }

    pub fn init_decrypt(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        return self.init(key, iv, ws::AES_DECRYPTION as i32);
    }

    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size == out_size {
            let rc = unsafe {
                ws::wc_AesCbcEncrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
            };
            if rc != 0 {
                Err(rc)
            } else {
                Ok(())
            }
        } else {
            Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG)
        }
    }

    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size == out_size {
            let rc = unsafe {
                ws::wc_AesCbcDecrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
            };
            if rc != 0 {
                Err(rc)
            } else {
                Ok(())
            }
        } else {
            Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG)
        }
    }
}
impl Drop for CBC {
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct CCM {
    ws_aes: ws::Aes,
}

pub struct CFB {
    ws_aes: ws::Aes,
}

pub struct CTR {
    ws_aes: ws::Aes,
}

pub struct CTS {
    ws_aes: ws::Aes,
}

pub struct EAX {
    ws_aes: ws::Aes,
}

pub struct EAXStream {
    ws_aeseax: ws::AesEax,
}

pub struct ECB {
    ws_aes: ws::Aes,
}
impl ECB {
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let ecb = ECB {ws_aes};
        Ok(ecb)
    }

    fn init(&mut self, key: &[u8], dir: i32) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let rc = unsafe {
            ws::wc_AesSetKey(&mut self.ws_aes, key_ptr, key_size,
                null(), dir)
        };
        if rc != 0 {
            Err(rc)
        } else {
            Ok(())
        }
    }

    pub fn init_encrypt(&mut self, key: &[u8]) -> Result<(), i32> {
        return self.init(key, ws::AES_ENCRYPTION as i32);
    }

    pub fn init_decrypt(&mut self, key: &[u8]) -> Result<(), i32> {
        return self.init(key, ws::AES_DECRYPTION as i32);
    }

    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size == out_size {
            let rc = unsafe {
                ws::wc_AesEcbEncrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
            };
            if rc != 0 {
                Err(rc)
            } else {
                Ok(())
            }
        } else {
            Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG)
        }
    }

    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size == out_size {
            let rc = unsafe {
                ws::wc_AesEcbDecrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
            };
            if rc != 0 {
                Err(rc)
            } else {
                Ok(())
            }
        } else {
            Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG)
        }
    }
}
impl Drop for ECB {
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct GCM {
    ws_aes: ws::Aes,
}

pub struct OFB {
    ws_aes: ws::Aes,
}

pub struct XTS {
    ws_xtsaes: ws::XtsAes,
}

pub struct XTSStream {
    ws_xtsaes: ws::XtsAes,
}

/// Interface to wolfCrypt Advanced Encryption Standard (AES) operations.
///
/// This struct wraps the wolfssl `Aes` type, providing a high-level API
/// for encrypting and decrypting blocks of data using various AES cipher modes.
/// The `Drop` implementation ensures that the underlying wolfSSL AES context
/// is correctly freed when the `AES` struct instance goes out of scope,
/// preventing memory leaks.
//pub struct AES {
//    ws_aes: ws::Aes,
//    mode: CipherMode,
//}

//impl AES {
//    /// Create and initialize a new `AES` instance.
//    ///
//    /// # Parameters
//    ///
//    /// * `mode`: AES cipher mode (e.g. GCM, CTR, etc.).
//    /// * `key`: Encryption/decryption key.
//    /// * `iv`: Initialization vector to use (optional).
//    ///
//    /// # Returns
//    ///
//    /// A Result which is Ok(AES) on success or an Err containing the wolfSSL
//    /// library return code on failure.
//    pub fn new<KeyT, IvT>(mode: CipherMode, key: &[KeyT], iv: Option<&[IvT]>) -> Result<Self, i32> {
//        let mut ws_aes: MaybeUninit<ws::Aes> = MaybeUninit::uninit();
//        let rc = unsafe { ws::wc_AesInit(ws_aes.as_mut_ptr()) };
//        if rc != 0 {
//            return Err(rc);
//        }
//        let ws_aes = unsafe { ws_aes.assume_init() };
//        let key_ptr = key.as_ptr() as *const u8;
//        let key_size = (key.len() * size_of::<KeyT>()) as u32;
//        let iv_ptr = match iv {
//            Some(iv) => iv.as_ptr() as *const u8,
//            None => std::ptr::null(),
//        }
//        let iv_size = match iv {
//            Some(iv) => (iv.len() * size_of::<IvT>()) as u32,
//            None => 0u32,
//        }
//        match mode {
//            CCM => {
//                wc_AesInit,
//                wc_AesCcmSetKey,
//                wc_AesCcmEncrypt/wc_AesCcmDecrypt, - nonce, authTag, authIn
//            }
//            CFB => {
//                wc_AesInit,
//                wc_AesSetKey,
//                wc_AesCfbEncrypt/wc_AesCfbDecrypt,
//            }
//            CTR => {
//                wc_AesInit,
//                wc_AesSetKeyDirect,
//                wc_AesCtrEncrypt,
//                unsafe { ws::wc_AesCtrSetKey(&mut ws_aes, key_ptr, key_size, iv_ptr, iv_size); }
//            }
//            CTS => {
//                // one shot:
//                wc_AesCtrEncrypt/wc_AesCtsDecrypt,
//                // incremental (use AES struct):
//                wc_AesInit,
//                wc_AesSetKey,
//                wc_AesCtsEncryptUpdate/wc_AesCtsDecryptUpdate,
//                wc_AesCtsEncryptFinal/wc_AesCtsDecryptFinal,
//            }
//            EAX => { // AesEax struct,
//                // one shot mode:
//                wc_AesEaxEncryptAuth/wc_AesEaxDecryptAuth,
//                // incremental (use AesEax struct):
//                wc_AesEaxInit,
//                wc_AesEaxEncryptUpdate/wc_AesEaxDecryptUpdate/wc_AesEaxAuthDataUpdate,
//                wc_AesEaxEncryptFinal/wc_AesEaxDecryptFinal,
//            }
//            GCM => {
//                // one shot:
//                wc_AesInit,
//                wc_AesGcmSetKey,
//                wc_AesGcmEncrypt/wc_AesGcmDecrypt, -- iv, authin, authout,
//                // chunking:
//                wc_AesInit,
//                wc_AesGcmEncryptInit/wc_AesGcmDecryptInit, -- key, iv,
//                wc_AesGcmEncryptUpdate/wc_AesGcmDecryptUpdate, -- authin
//                wc_AesGcmEncryptFinal/wc_AesGcmDecryptFinal, -- authtag (out) / authtag (in)
//            }
//            OFB => {
//                wc_AesInit,
//                wc_AesSetKey,
//                wc_AesOfbEncrypt/wc_AesOfbDecrypt,
//            }
//            XTS => { // XtsAes struct
//                // one shot:
//                wc_AesXtsInit,
//                wc_AesXtsSetKeyNoInit,
//                wc_AesXtsEncrypt/wc_AesXtsDecrypt, - tweak
//                wc_AesXtsFree,
//                // chunking:
//                wc_AesXtsInit,
//                wc_AesXtsSetKeyNoInit,
//                wc_AesXtsEncryptInit/wc_AesXtsDecryptInit,
//                wc_AesXtsEncryptUpdate/wc_AesXtsDecryptUpdate,
//                wc_AesXtsEncryptFinal/wc_AesXtsDecryptFinal,
//            }
//        }
//        let aes = AES {
//            ws_aes,
//            mode,
//        };
//        Ok(aes)
//    }
//}

//impl Drop for AES {
//    /// Safely free the underlying wolfSSL AES context.
//    ///
//    /// This calls the `wc_AesFree` wolfssl library function.
//    ///
//    /// The Rust Drop trait guarantees that this method is called when the AES
//    /// struct instance goes out of scope, automatically cleaning up resources
//    /// and preventing memory leaks.
//    fn drop(&mut self) {
//        unsafe { ws::wc_AesFree(&mut self.aes); }
//    }
//}

fn new_ws_aes() -> Result<ws::Aes, i32> {
    let mut ws_aes: MaybeUninit<ws::Aes> = MaybeUninit::uninit();
    let rc = unsafe {
        ws::wc_AesInit(ws_aes.as_mut_ptr(), null_mut(), ws::INVALID_DEVID)
    };
    if rc != 0 {
        return Err(rc);
    }
    let ws_aes = unsafe { ws_aes.assume_init() };
    Ok(ws_aes)
}
