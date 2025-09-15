use wolfssl_sys as ws;

use std::mem::MaybeUninit;
use std::mem;

pub struct RNG {
    wc_rng: ws::WC_RNG,
}

impl RNG {
    pub fn new() -> Result<Self, i32> {
        let mut rng: MaybeUninit<RNG> = MaybeUninit::uninit();
        let rc = unsafe { ws::wc_InitRng(&mut (*rng.as_mut_ptr()).wc_rng) };
        if rc == 0 {
            let rng = unsafe { rng.assume_init() };
            Ok(rng)
        } else {
            Err(rc)
        }
    }

    pub fn generate_byte(&mut self) -> Result<u8, i32> {
        let mut b: u8 = 0;
        let rc = unsafe { ws::wc_RNG_GenerateByte(&mut self.wc_rng, &mut b) };
        if rc == 0 {
            Ok(b)
        } else {
            Err(rc)
        }
    }

    pub fn generate_block<T>(&mut self, buf: &mut [T]) -> Result<(), i32> {
        let ptr = buf.as_mut_ptr() as *mut u8;
        let size: u32 = (buf.len() * mem::size_of::<T>()) as u32;
        let rc = unsafe { ws::wc_RNG_GenerateBlock(&mut self.wc_rng, ptr, size) };
        if rc == 0 {
            Ok(())
        } else {
            Err(rc)
        }
    }
}

impl Drop for RNG {
    fn drop(&mut self) {
        unsafe { ws::wc_FreeRng(&mut self.wc_rng); }
    }
}
