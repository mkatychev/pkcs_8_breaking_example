use pkcs_8_breaking_example::*;

fn main() {
    let keypair = Keypair::decrypt_from_file_07("./pk.der", b"password").unwrap();
    println!("Public Key: {:x?}", keypair.vk.as_ref());
}
