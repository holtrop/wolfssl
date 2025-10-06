use wolfssl::wolfcrypt::ecc::*;
use wolfssl::wolfcrypt::random::RNG;

#[test]
fn test_ecc_generate() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let mut ecc = ECC::generate(32, &mut rng).expect("Error with generate()");
    ecc.check().expect("Error with check()");
}

#[test]
fn test_ecc_generate_ex() {
    let mut rng = RNG::new().expect("Failed to create RNG");
    let curve_id = ECC::SECP256R1;
    let curve_size = ECC::get_curve_size_from_id(curve_id).expect("Error with get_curve_size_from_id()");
    let mut ecc = ECC::generate_ex(curve_size, &mut rng, curve_id).expect("Error with generate()");
    ecc.check().expect("Error with check()");
}
