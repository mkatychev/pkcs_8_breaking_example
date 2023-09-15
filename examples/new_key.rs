use rust_crypto_example::*;

fn main() {
    let keypair = Keypair::random();
    let der_file = keypair.encrypt_to_file_07("./pk.der", b"password").unwrap();
}
