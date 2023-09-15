use std::path::Path;

use ed25519_zebra::{SigningKey, VerificationKey};
use rand::{thread_rng, Rng};
use zeroize::Zeroizing;

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

const ED25519_OID: pkcs8_07::ObjectIdentifier = pkcs8_07::ObjectIdentifier::new("1.3.101.112");

pub struct Keypair {
    pub vk: VerificationKey,
    sk: SigningKey,
}

impl Keypair {
    pub fn random() -> Self {
        let key = ed25519_zebra::SigningKey::new(rand::thread_rng());
        Self::new(key)
    }
    pub fn new(sk: SigningKey) -> Self {
        Self {
            vk: VerificationKey::from(&sk),
            sk,
        }
    }
    // PKCS8 0.7 methods
    pub fn encrypt_to_file_07(&self, path: impl AsRef<Path>, password: &[u8]) -> Result<(), Error> {
        let encrypted = self.encrypt_07(password)?;
        encrypted.write_der_file(path)?;

        Ok(())
    }

    pub fn decrypt_from_file_07(path: impl AsRef<Path>, password: &[u8]) -> Result<Self, Error> {
        let encrypted = pkcs8_07::EncryptedPrivateKeyDocument::read_der_file(path.as_ref())?;
        let keypair = Self::decrypt_07(encrypted, password)?;
        Ok(keypair)
    }

    pub fn encrypt_07(
        &self,
        password: &[u8],
    ) -> Result<pkcs8_07::EncryptedPrivateKeyDocument, Error> {
        let z_pk = Zeroizing::new(self.sk.as_ref().to_vec());
        let private_key = z_pk.as_ref();

        let public_key = Some(self.vk.as_ref());
        let algorithm = pkcs8_07::AlgorithmIdentifier {
            oid: ED25519_OID,
            parameters: None,
        };

        // DER V2 includes public key
        let pk_info = pkcs8_07::PrivateKeyInfo {
            algorithm,
            private_key,
            attributes: None,
            public_key,
        };

        let mut rng = thread_rng();
        let salt = rng.gen::<[u8; 16]>();
        let aes_iv = rng.gen::<[u8; 16]>();

        // Uses pbkdf2 sha256 aes256cbc parameters
        let pbes2_params =
            pkcs8_07::pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(2048, &salt, &aes_iv)
                .map_err(|e| e.to_string())?;

        // convert pk_info
        let pk_doc = pk_info.to_der();

        // encrypt the private key document;
        let encrypted = pk_doc
            .encrypt_with_params(pbes2_params, password)
            .map_err(|e| e.to_string())?;

        Ok(encrypted)
    }

    pub fn decrypt_07(
        encrypted: pkcs8_07::EncryptedPrivateKeyDocument,
        password: &[u8],
    ) -> Result<Self, Error> {
        let pk_doc = encrypted.decrypt(password).map_err(|e| e.to_string())?;
        let pk_info = pk_doc.private_key_info();
        let sk =
            ed25519_zebra::SigningKey::try_from(pk_info.private_key).map_err(|e| e.to_string())?;
        Ok(Self::new(sk))
    }

    // PKCS8 0.10 methods
    pub fn decrypt_from_file(path: impl AsRef<Path>, password: &[u8]) -> Result<Self, Error> {
        let doc = std::fs::read(path.as_ref())?;
        let info = pkcs8::EncryptedPrivateKeyInfo::try_from(doc.as_ref())?;
        let keypair = Self::decrypt(info, password)?;
        Ok(keypair)
    }

    pub fn decrypt(
        encrypted: pkcs8::EncryptedPrivateKeyInfo,
        password: &[u8],
    ) -> Result<Self, Error> {
        let secret = encrypted.decrypt(password)?;
        let pk_info: pkcs8::PrivateKeyInfo = secret.decode_msg()?;
        let sk =
            ed25519_zebra::SigningKey::try_from(pk_info.private_key).map_err(|e| e.to_string())?;
        Ok(Self::new(sk))
    }
}
