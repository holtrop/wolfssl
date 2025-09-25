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

pub struct GCMStream {
    ws_aes: ws::Aes,
}
impl GCMStream {
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let gcmstream = GCMStream {ws_aes};
        Ok(gcmstream)
    }

    pub fn init(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        let iv_size = iv.len() as u32;
        let rc = unsafe {
            ws::wc_AesGcmInit(&mut self.ws_aes, key_ptr, key_size, iv_ptr, iv_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn encrypt_update<I,O>(&mut self, din: &[I], dout: &mut [O],
            auth: &[u8]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = auth.len() as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesGcmEncryptUpdate(&mut self.ws_aes, out_ptr,
                in_ptr, in_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn encrypt_final(&mut self, auth_tag: &mut [u8]) -> Result<(), i32> {
        let auth_tag_ptr = auth_tag.as_ptr() as *mut u8;
        let auth_tag_size = auth_tag.len() as u32;
        let rc = unsafe {
            ws::wc_AesGcmEncryptFinal(&mut self.ws_aes, auth_tag_ptr, auth_tag_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt_update<I,O>(&mut self, din: &[I], dout: &mut [O],
            auth: &[u8]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let auth_ptr = auth.as_ptr() as *const u8;
        let auth_size = auth.len() as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesGcmDecryptUpdate(&mut self.ws_aes, out_ptr,
                in_ptr, in_size,
                auth_ptr, auth_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt_final(&mut self, auth_tag: &[u8]) -> Result<(), i32> {
        let auth_tag_ptr = auth_tag.as_ptr() as *const u8;
        let auth_tag_size = auth_tag.len() as u32;
        let rc = unsafe {
            ws::wc_AesGcmDecryptFinal(&mut self.ws_aes, auth_tag_ptr, auth_tag_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
impl Drop for GCMStream {
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct OFB {
    ws_aes: ws::Aes,
}
impl OFB {
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let ofb = OFB {ws_aes};
        Ok(ofb)
    }

    pub fn init(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let iv_ptr = iv.as_ptr() as *const u8;
        if iv.len() as u32 != ws::WC_AES_BLOCK_SIZE {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesSetKey(&mut self.ws_aes, key_ptr, key_size, iv_ptr,
                ws::AES_ENCRYPTION as i32)
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
            ws::wc_AesOfbEncrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
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
            ws::wc_AesOfbDecrypt(&mut self.ws_aes, out_ptr, in_ptr, in_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
impl Drop for OFB {
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct XTS {
    ws_xtsaes: ws::XtsAes,
}
impl XTS {
    pub fn new() -> Result<Self, i32> {
        let ws_xtsaes = new_ws_xtsaes()?;
        let xts = XTS {ws_xtsaes};
        Ok(xts)
    }

    fn init(&mut self, key: &[u8], dir: i32) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let rc = unsafe {
            ws::wc_AesXtsSetKeyNoInit(&mut self.ws_xtsaes, key_ptr, key_size,
                dir)
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

    pub fn encrypt<I,O>(&mut self, din: &[I], dout: &mut [O], tweak: &[u8]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let tweak_ptr = tweak.as_ptr() as *const u8;
        let tweak_size = tweak.len() as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesXtsEncrypt(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size,
                tweak_ptr, tweak_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn encrypt_consecutive_sectors<I,O>(&mut self, din: &[I], dout: &mut [O],
            sector: u64, sector_size: u32) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesXtsEncryptConsecutiveSectors(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, sector, sector_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt<I,O>(&mut self, din: &[I], dout: &mut [O], tweak: &[u8]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        let tweak_ptr = tweak.as_ptr() as *const u8;
        let tweak_size = tweak.len() as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesXtsDecrypt(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size,
                tweak_ptr, tweak_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt_consecutive_sectors<I,O>(&mut self, din: &[I], dout: &mut [O],
            sector: u64, sector_size: u32) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesXtsDecryptConsecutiveSectors(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, sector, sector_size)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
impl Drop for XTS {
    fn drop(&mut self) {
        unsafe { ws::wc_AesXtsFree(&mut self.ws_xtsaes); }
    }
}

pub struct XTSStream {
    ws_xtsaes: ws::XtsAes,
    ws_xtsaesstreamdata: ws::XtsAesStreamData,
}
impl XTSStream {
    pub fn new() -> Result<Self, i32> {
        let ws_xtsaes = new_ws_xtsaes()?;
        let ws_xtsaesstreamdata: MaybeUninit<ws::XtsAesStreamData> = MaybeUninit::uninit();
        let ws_xtsaesstreamdata = unsafe { ws_xtsaesstreamdata.assume_init() };
        let xtsstream = XTSStream {ws_xtsaes, ws_xtsaesstreamdata};
        Ok(xtsstream)
    }

    pub fn init_encrypt(&mut self, key: &[u8], tweak: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let rc = unsafe {
            ws::wc_AesXtsSetKeyNoInit(&mut self.ws_xtsaes, key_ptr, key_size,
                ws::AES_ENCRYPTION as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        let tweak_ptr = tweak.as_ptr() as *const u8;
        let tweak_size = tweak.len() as u32;
        let rc = unsafe {
            ws::wc_AesXtsEncryptInit(&mut self.ws_xtsaes, tweak_ptr, tweak_size,
                &mut self.ws_xtsaesstreamdata)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn init_decrypt(&mut self, key: &[u8], tweak: &[u8]) -> Result<(), i32> {
        let key_ptr = key.as_ptr() as *const u8;
        let key_size = key.len() as u32;
        let rc = unsafe {
            ws::wc_AesXtsSetKeyNoInit(&mut self.ws_xtsaes, key_ptr, key_size,
                ws::AES_DECRYPTION as i32)
        };
        if rc != 0 {
            return Err(rc);
        }
        let tweak_ptr = tweak.as_ptr() as *const u8;
        let tweak_size = tweak.len() as u32;
        let rc = unsafe {
            ws::wc_AesXtsDecryptInit(&mut self.ws_xtsaes, tweak_ptr, tweak_size,
                &mut self.ws_xtsaesstreamdata)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn encrypt_update<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesXtsEncryptUpdate(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, &mut self.ws_xtsaesstreamdata)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn encrypt_final<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesXtsEncryptFinal(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, &mut self.ws_xtsaesstreamdata)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt_update<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesXtsDecryptUpdate(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, &mut self.ws_xtsaesstreamdata)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }

    pub fn decrypt_final<I,O>(&mut self, din: &[I], dout: &mut [O]) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesXtsDecryptFinal(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, &mut self.ws_xtsaesstreamdata)
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(())
    }
}
impl Drop for XTSStream {
    fn drop(&mut self) {
        unsafe { ws::wc_AesXtsFree(&mut self.ws_xtsaes); }
    }
}

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

fn new_ws_xtsaes() -> Result<ws::XtsAes, i32> {
    let mut ws_xtsaes: MaybeUninit<ws::XtsAes> = MaybeUninit::uninit();
    let rc = unsafe {
        ws::wc_AesXtsInit(ws_xtsaes.as_mut_ptr(), null_mut(), ws::INVALID_DEVID)
    };
    if rc != 0 {
        return Err(rc);
    }
    let ws_xtsaes = unsafe { ws_xtsaes.assume_init() };
    Ok(ws_xtsaes)
}
