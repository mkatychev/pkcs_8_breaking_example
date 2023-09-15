fn main() {
    let keypair = rust_crypto_example::Keypair::random();
    let der_file = keypair.encrypt_to_file("./pk.der", b"password").unwrap();
}
