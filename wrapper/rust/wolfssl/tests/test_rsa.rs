use wolfssl::wolfcrypt::random::RNG;
use wolfssl::wolfcrypt::rsa::*;

#[test]
fn test_rsa_generate() {
    let mut rng = RNG::new().expect("Error creating RNG");
    let mut rsa = RSA::generate(2048, 65537, &mut rng).expect("Error with generate()");
    rsa.check().expect("Error with check()");
    let encrypt_size = rsa.get_encrypt_size().expect("Error with get_encrypt_size()");
    assert_eq!(encrypt_size, 256);
}
