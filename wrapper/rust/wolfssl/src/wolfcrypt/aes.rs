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
            ws::wc_AesSetKey(&mut self.ws_aes, key_ptr, key_size, iv_ptr, dir)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
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
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesCbcEncrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesCbcDecrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
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
impl CCM {
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let ccm = CCM {ws_aes};
        Ok(ccm)
    }

    pub fn init(&mut self, key: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let rc = unsafe {
            ws::wc_AesCcmSetKey(&mut self.ws_aes, key_ptr, key_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn encrypt<I,O,N,A>(&mut self, din: &[I], dout: &mut [O], nonce: &[N], auth: &[A], auth_tag: &mut [A]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let nonce_ptr = nonce.as_ptr() as *const u8;
        let nonce_size = (nonce.len() * size_of::<O>()) as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = (auth.len() * size_of::<O>()) as u32;
        let auth_tag_ptr = auth_tag.as_ptr() as *mut u8;
        let auth_tag_size = (auth_tag.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesCcmEncrypt(&mut self.ws_aes, out_ptr,
                in_ptr, in_size,
                nonce_ptr, nonce_size,
                auth_tag_ptr, auth_tag_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt<I,O,N,A>(&mut self, din: &[I], dout: &mut [O], nonce: &[N], auth: &[A], auth_tag: &[A]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let nonce_ptr = nonce.as_ptr() as *const u8;
        let nonce_size = (nonce.len() * size_of::<O>()) as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = (auth.len() * size_of::<O>()) as u32;
        let auth_tag_ptr = auth_tag.as_ptr() as *const u8;
        let auth_tag_size = (auth_tag.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesCcmDecrypt(&mut self.ws_aes, out_ptr,
                in_ptr, in_size,
                nonce_ptr, nonce_size,
                auth_tag_ptr, auth_tag_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
impl Drop for CCM {
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct CFB {
    ws_aes: ws::Aes,
}
impl CFB {
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let cfb = CFB {ws_aes};
        Ok(cfb)
    }

    pub fn init(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        if iv.len() as u32 != ws::WC_AES_BLOCK_SIZE {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesSetKey(&mut self.ws_aes, key_ptr, key_size,
                iv_ptr, ws::AES_ENCRYPTION as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesCfbEncrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn encrypt1<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesCfb1Encrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn encrypt8<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesCfb8Encrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesCfbDecrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt1<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesCfb1Decrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt8<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesCfb8Decrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
impl Drop for CFB {
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct CTR {
    ws_aes: ws::Aes,
}
impl CTR {
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let ctr = CTR {ws_aes};
        Ok(ctr)
    }

    pub fn init(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        if iv.len() as u32 != ws::WC_AES_BLOCK_SIZE {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesSetKeyDirect(&mut self.ws_aes, key_ptr, key_size,
                iv_ptr, ws::AES_ENCRYPTION as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    fn encrypt_decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesCtrEncrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        return self.encrypt_decrypt(din, dout);
    }

    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        return self.encrypt_decrypt(din, dout);
    }
}
impl Drop for CTR {
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct EAX {
    ws_aeseax: ws::AesEax,
}
impl EAX {
    pub fn encrypt<I,O>(key: &[u8], nonce: &[u8], auth: &[u8], auth_tag: &mut [u8],
            din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let nonce_ptr = nonce.as_ptr() as *const u8;
        let nonce_size = nonce.len() as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = auth.len() as u32;
        let auth_tag_ptr = auth_tag.as_ptr() as *mut u8;
        let auth_tag_size = auth_tag.len() as u32;
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = din.len() as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = dout.len() as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesEaxEncryptAuth(key_ptr, key_size, out_ptr,
                in_ptr, in_size, nonce_ptr, nonce_size,
                auth_tag_ptr, auth_tag_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt<I,O>(key: &[u8], nonce: &[u8], auth: &[u8], auth_tag: &[u8],
            din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let nonce_ptr = nonce.as_ptr() as *const u8;
        let nonce_size = nonce.len() as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = auth.len() as u32;
        let auth_tag_ptr = auth_tag.as_ptr() as *const u8;
        let auth_tag_size = auth_tag.len() as u32;
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = din.len() as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = dout.len() as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesEaxDecryptAuth(key_ptr, key_size, out_ptr,
                in_ptr, in_size, nonce_ptr, nonce_size,
                auth_tag_ptr, auth_tag_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
impl Drop for EAX {
    fn drop(&mut self) {
        unsafe { ws::wc_AesEaxFree(&mut self.ws_aeseax); }
    }
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
            return Err(rc);
        }
        Ok(())
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
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesEcbEncrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesEcbDecrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
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
impl GCM {
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let gcm = GCM {ws_aes};
        Ok(gcm)
    }

    pub fn init(&mut self, key: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let rc = unsafe {
            ws::wc_AesGcmSetKey(&mut self.ws_aes, key_ptr, key_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O], iv: &[u8],
            auth: &[u8], auth_tag: &mut [u8]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        let iv_size = iv.len() as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = auth.len() as u32;
        let auth_tag_ptr = auth_tag.as_ptr() as *mut u8;
        let auth_tag_size = auth_tag.len() as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesGcmEncrypt(&mut self.ws_aes, out_ptr,
                in_ptr, in_size,
                iv_ptr, iv_size,
                auth_tag_ptr, auth_tag_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O], iv: &[u8],
            auth: &[u8], auth_tag: &[u8]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        let iv_size = iv.len() as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = auth.len() as u32;
        let auth_tag_ptr = auth_tag.as_ptr() as *const u8;
        let auth_tag_size = auth_tag.len() as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesGcmDecrypt(&mut self.ws_aes, out_ptr,
                in_ptr, in_size,
                iv_ptr, iv_size,
                auth_tag_ptr, auth_tag_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
impl Drop for GCM {
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}
//                // chunking:
//                wc_AesInit,
//                wc_AesGcmEncryptInit/wc_AesGcmDecryptInit, -- key, iv,
//                wc_AesGcmEncryptUpdate/wc_AesGcmDecryptUpdate, -- authin
//                wc_AesGcmEncryptFinal/wc_AesGcmDecryptFinal, -- authtag (out) / authtag (in)

pub struct OFB {
    ws_aes: ws::Aes,
}
//            OFB => {
//                wc_AesInit,
//                wc_AesSetKey,
//                wc_AesOfbEncrypt/wc_AesOfbDecrypt,
//            }

pub struct XTS {
    ws_xtsaes: ws::XtsAes,
}
//            XTS => { // XtsAes struct
//                // one shot:
//                wc_AesXtsInit,
//                wc_AesXtsSetKeyNoInit,
//                wc_AesXtsEncrypt/wc_AesXtsDecrypt, - tweak
//                wc_AesXtsFree,

pub struct XTSStream {
    ws_xtsaes: ws::XtsAes,
}
//                // chunking:
//                wc_AesXtsInit,
//                wc_AesXtsSetKeyNoInit,
//                wc_AesXtsEncryptInit/wc_AesXtsDecryptInit,
//                wc_AesXtsEncryptUpdate/wc_AesXtsDecryptUpdate,
//                wc_AesXtsEncryptFinal/wc_AesXtsDecryptFinal,

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
