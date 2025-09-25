/*!
This crate provides a Rust wrapper for the wolfCrypt library's Advanced
Encryption Standard (AES) functionality.

It leverages the `wolfssl-sys` crate for low-level FFI bindings, encapsulating
the raw C functions in a memory-safe and easy-to-use Rust API.
*/

use std::mem::{size_of, MaybeUninit};
use std::ptr::{null, null_mut};
use wolfssl_sys as ws;

/// Advanced Encryption Standard (AES) Cipher Block Chaining (CBC) support.
///
/// # Example
/// ```rust
/// use wolfssl::wolfcrypt::aes::*;
/// let mut cbc = CBC::new().expect("Failed to create CBC");
/// let key: &[u8; 16] = b"0123456789abcdef";
/// let iv: &[u8; 16] = b"1234567890abcdef";
/// let msg: [u8; 16] = [
///     0x6e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
///     0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20,
/// ];
/// let expected_cipher: [u8; 16] = [
///     0x95, 0x94, 0x92, 0x57, 0x5f, 0x42, 0x81, 0x53,
///     0x2c, 0xcc, 0x9d, 0x46, 0x77, 0xa2, 0x33, 0xcb
/// ];
/// cbc.init_encrypt(key, iv).expect("Error with init_encrypt()");
/// let mut cipher: [u8; 16] = [0; 16];
/// cbc.encrypt(&msg, &mut cipher).expect("Error with encrypt()");
/// assert_eq!(&cipher, &expected_cipher);
/// let mut plain_out = [0; 16];
/// cbc.init_decrypt(key, iv).expect("Error with init_decrypt()");
/// cbc.decrypt(&cipher, &mut plain_out).expect("Error with decrypt()");
/// assert_eq!(&plain_out, &msg);
/// ```
pub struct CBC {
    ws_aes: ws::Aes,
}
impl CBC {
    /// Create a new `CBC` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(CBC) on success or an Err containing the wolfSSL
    /// library return code on failure.
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

    /// Initialize a CBC instance for encryption.
    ///
    /// This method must be called before calling `encrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `iv`: A slice containing the initialization vector (IV) to use. The
    /// IV must be 16 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init_encrypt(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        return self.init(key, iv, ws::AES_ENCRYPTION as i32);
    }

    /// Initialize a CBC instance for decryption.
    ///
    /// This method must be called before calling `decrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the decryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `iv`: A slice containing the initialization vector (IV) to use. The
    /// IV must be 16 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn init_decrypt(&mut self, key: &[u8], iv: &[u8]) -> Result<(), i32> {
        return self.init(key, iv, ws::AES_DECRYPTION as i32);
    }

    /// Encrypt data.
    ///
    /// The `init_encrypt()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: A slice containing the data to encrypt. The size of the data
    /// must be a multiple of 16 bytes.
    /// * `dout`: A slice in which to store the encrypted data. The size of
    /// the data must match that of the `din` slice.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
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

    /// Decrypt data.
    ///
    /// The `init_decrypt()` method must be called before calling this method.
    ///
    /// # Parameters
    ///
    /// * `din`: A slice containing the data to decrypt. The size of the data
    /// must be a multiple of 16 bytes.
    /// * `dout`: A slice in which to store the decrypted data. The size of
    /// the data must match that of the `din` slice.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
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
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

/// Advanced Encryption Standard (AES) counter with cipher block chaining
/// message authentication code (CCM) support.
///
/// # Example
/// ```rust
/// use wolfssl::wolfcrypt::aes::*;
/// let key: [u8; 16] = [
///     0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
///     0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
/// ];
/// let nonce: [u8; 13] = [
///     0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0,
///     0xa1, 0xa2, 0xa3, 0xa4, 0xa5
/// ];
/// let plaintext: [u8; 23] = [
///     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
///     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e
/// ];
/// let auth_data: [u8; 8] = [
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
/// ];
/// let expected_ciphertext: [u8; 23] = [
///     0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2,
///     0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
///     0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84
/// ];
/// let expected_auth_tag: [u8; 8] = [
///     0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0
/// ];
///
/// let mut ccm = CCM::new().expect("Failed to create CCM");
/// ccm.init(&key).expect("Error with init()");
/// let mut auth_tag_out: [u8; 8] = [0; 8];
/// let mut cipher_out: [u8; 23] = [0; 23];
/// ccm.encrypt(&plaintext, &mut cipher_out,
///     &nonce, &auth_data, &mut auth_tag_out).expect("Error with encrypt()");
/// assert_eq!(cipher_out, expected_ciphertext);
/// assert_eq!(auth_tag_out, expected_auth_tag);
/// ccm.init(&key).expect("Error with init()");
/// let mut plain_out: [u8; 23] = [0; 23];
/// ccm.decrypt(&cipher_out, &mut plain_out,
///     &nonce, &auth_data, &auth_tag_out).expect("Error with decrypt()");
/// assert_eq!(plain_out, plaintext);
/// ```
pub struct CCM {
    ws_aes: ws::Aes,
}
impl CCM {
    /// Create a new `CCM` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(CCM) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let ccm = CCM {ws_aes};
        Ok(ccm)
    }

    /// Initialize a CCM instance for encryption or decryption.
    ///
    /// This method must be called before calling `encrypt()` or `decrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
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
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct CFB {
    ws_aes: ws::Aes,
}
impl CFB {
    /// Create a new `CFB` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(CFB) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let cfb = CFB {ws_aes};
        Ok(cfb)
    }

    /// Initialize a CFB instance for encryption or decryption.
    ///
    /// This method must be called before calling `encrypt()`, `encrypt`()`,
    /// `encrypt8()`, `decrypt()`, `decrypt1()`, or `decrypt8()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `iv`: A slice containing the initialization vector (IV) to use. The
    /// IV must be 16 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
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
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct CTR {
    ws_aes: ws::Aes,
}
impl CTR {
    /// Create a new `CTR` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(CTR) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let ctr = CTR {ws_aes};
        Ok(ctr)
    }

    /// Initialize a CTR instance for encryption or decryption.
    ///
    /// This method must be called before calling `encrypt()` or `decrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `iv`: A slice containing the initialization vector (IV) to use. The
    /// IV must be 16 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
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
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct EAX {
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

pub struct ECB {
    ws_aes: ws::Aes,
}
impl ECB {
    /// Create a new `ECB` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(ECB) on success or an Err containing the wolfSSL
    /// library return code on failure.
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
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct GCM {
    ws_aes: ws::Aes,
}
impl GCM {
    /// Create a new `GCM` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(GCM) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let gcm = GCM {ws_aes};
        Ok(gcm)
    }

    /// Initialize a GCM instance for encryption or decryption.
    ///
    /// This method must be called before calling `encrypt()` or `decrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
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
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct GCMStream {
    ws_aes: ws::Aes,
}
impl GCMStream {
    /// Create a new `GCMStream` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(GCMStream) on success or an Err containing the
    /// wolfSSL library return code on failure.
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let gcmstream = GCMStream {ws_aes};
        Ok(gcmstream)
    }

    /// Initialize a GCMStream instance for encryption or decryption.
    ///
    /// This method must be called before calling `encrypt_update()`,
    /// `encrypt_final()`, `decrypt_update()`, or `decrypt_final()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `iv`: A slice containing the initialization vector (IV) to use.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
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
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct OFB {
    ws_aes: ws::Aes,
}
impl OFB {
    /// Create a new `OFB` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(OFB) on success or an Err containing the wolfSSL
    /// library return code on failure.
    pub fn new() -> Result<Self, i32> {
        let ws_aes = new_ws_aes()?;
        let ofb = OFB {ws_aes};
        Ok(ofb)
    }

    /// Initialize a OFB instance for encryption or decryption.
    ///
    /// This method must be called before calling `encrypt()` or `decrypt()`.
    ///
    /// # Parameters
    ///
    /// * `key`: A slice containing the encryption key to use. The key must be
    /// 16, 24, or 32 bytes in length.
    /// * `iv`: A slice containing the initialization vector (IV) to use. The
    /// IV must be 16 bytes in length.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(()) on success or an Err containing the wolfSSL
    /// library return code on failure.
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
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { ws::wc_AesFree(&mut self.ws_aes); }
    }
}

pub struct XTS {
    ws_xtsaes: ws::XtsAes,
}
impl XTS {
    /// Create a new `XTS` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(XTS) on success or an Err containing the wolfSSL
    /// library return code on failure.
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

    pub fn encrypt_sector<I,O>(&mut self, din: &[I], dout: &mut [O], sector: u64) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesXtsEncryptSector(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, sector)
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

    pub fn decrypt_sector<I,O>(&mut self, din: &[I], dout: &mut [O], sector: u64) -> Result<(), i32> {
        let in_ptr = din.as_ptr() as *const u8;
        let in_size = (din.len() * size_of::<I>()) as u32;
        let out_ptr = dout.as_ptr() as *mut u8;
        let out_size = (dout.len() * size_of::<O>()) as u32;
        if in_size != out_size {
            return Err(ws::wolfCrypt_ErrorCodes_BAD_FUNC_ARG);
        }
        let rc = unsafe {
            ws::wc_AesXtsDecryptSector(&mut self.ws_xtsaes, out_ptr,
                in_ptr, in_size, sector)
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
    /// Safely free the wolfSSL resources.
    fn drop(&mut self) {
        unsafe { ws::wc_AesXtsFree(&mut self.ws_xtsaes); }
    }
}

pub struct XTSStream {
    ws_xtsaes: ws::XtsAes,
    ws_xtsaesstreamdata: ws::XtsAesStreamData,
}
impl XTSStream {
    /// Create a new `XTSStream` instance.
    ///
    /// # Returns
    ///
    /// A Result which is Ok(XTSStream) on success or an Err containing the
    /// wolfSSL library return code on failure.
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
    /// Safely free the wolfSSL resources.
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
