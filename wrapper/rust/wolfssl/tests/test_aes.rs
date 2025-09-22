use wolfssl::wolfcrypt::aes::*;

#[test]
fn test_ecb_encrypt_decrypt() {
    let mut ecb = ECB::new().expect("Failed to create ECB");
    let key_128: &[u8; 16] = b"0123456789abcdef";
    let msg: [u8; 16] = [
        0x6e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20
    ];
    let verify_ecb_128: [u8; 16] = [
        0xd0, 0xc9, 0xd9, 0xc9, 0x40, 0xe8, 0x97, 0xb6,
        0xc8, 0x8c, 0x33, 0x3b, 0xb5, 0x8f, 0x85, 0xd1
    ];
    ecb.init_encrypt(key_128).expect("Error with init_encrypt()");
    let mut outbuf: [u8; 16] = [0; 16];
    ecb.encrypt(&msg, &mut outbuf).expect("Error with encrypt()");
    assert_eq!(&outbuf, &verify_ecb_128);
    outbuf = [0; 16];
    ecb.init_decrypt(key_128).expect("Error with init_decrypt()");
    ecb.decrypt(&verify_ecb_128, &mut outbuf).expect("Error with decrypt()");
    assert_eq!(&outbuf, &msg);
}
