use wolfssl::wolfcrypt::random::RNG;
use wolfssl::wolfcrypt::rsa::*;

#[test]
fn test_rsa_generate() {
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut rsa = RSA::generate(2048, 65537, &mut rng).expect("Error with generate()");
    rsa.check().expect("Error with check()");
    let encrypt_size = rsa.get_encrypt_size().expect("Error with get_encrypt_size()");
    assert_eq!(encrypt_size, 256);
    let mut e: [u8; 256] = [0; 256];
    let mut e_size: u32 = 0;
    let mut n: [u8; 256] = [0; 256];
    let mut n_size: u32 = 0;
    let mut d: [u8; 256] = [0; 256];
    let mut d_size: u32 = 0;
    let mut p: [u8; 256] = [0; 256];
    let mut p_size: u32 = 0;
    let mut q: [u8; 256] = [0; 256];
    let mut q_size: u32 = 0;
    rsa.export_key(&mut e, &mut e_size, &mut n, &mut n_size,
        &mut d, &mut d_size, &mut p, &mut p_size, &mut q, &mut q_size).expect("Error with export_key()");
    assert_ne!(e, [0; 256]);
    assert!(e_size > 0);
    assert_ne!(n, [0; 256]);
    assert!(n_size > 0);
    assert_ne!(d, [0; 256]);
    assert!(d_size > 0);
    assert_ne!(p, [0; 256]);
    assert!(p_size > 0);
    assert_ne!(q, [0; 256]);
    assert!(q_size > 0);
}
