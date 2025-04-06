use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base16ct::lower::encode_string as hex_encode;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha2::{Digest, Sha256};

use crate::Result;

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloudSecurityProvider {
    MSmartHome,
    Meiju,
    NetHomePlus,
    ArtisonClima,
}

pub trait CloudSecurity {
    fn get_iot_key(&self) -> &[u8];
    fn get_hmac_key(&self) -> &[u8];
    fn get_login_key(&self) -> &[u8];

    /// Generate a HMAC signature for the provided data and random data. Returns a hex encoded string.
    fn sign(&self, data: &[u8], random_data: &[u8]) -> Result<String> {
        let mut mac = HmacSha256::new_from_slice(&self.get_hmac_key())?;
        mac.update([self.get_iot_key(), data, random_data].concat().as_slice());
        let result = mac.finalize();

        Ok(hex_encode(&result.into_bytes()))
    }
    /// Encrypt the password for the cloud API. Returns a hex encoded string.
    fn encrypt_password(&self, login_id: &str, password: &str) -> String {
        let h1 = Sha256::digest(password);
        let h2 = Sha256::digest(
            [login_id.as_bytes(), &h1, &self.get_login_key()]
                .concat()
                .as_slice(),
        );

        hex_encode(&h2)
    }
}

trait ProxiedSecurity: CloudSecurity {
    fn get_app_key(&self) -> &[u8];

    fn encrypt_iam_password(&self, login_id: &str, password: &str) -> String;

    fn get_app_key_and_iv(&self) -> (Vec<u8>, Vec<u8>) {
        let hash = Sha256::digest(self.get_app_key());

        (hash[0..16].to_vec(), hash[16..32].to_vec())
    }

    fn encrypt_aes_app_key(&self, data: &[u8]) -> Vec<u8> {
        let (app_key, iv) = self.get_app_key_and_iv();

        let ciphertext = Aes128CbcEnc::new(app_key.as_slice().into(), iv.as_slice().into())
            .encrypt_padded_vec_mut::<Pkcs7>(data);

        ciphertext
    }

    fn decrypt_aes_app_key(&self, data: &[u8]) -> Result<Vec<u8>> {
        let (app_key, iv) = self.get_app_key_and_iv();

        let plaintext = Aes128CbcDec::new(app_key.as_slice().into(), iv.as_slice().into())
            .decrypt_padded_vec_mut::<Pkcs7>(&data)?;

        Ok(plaintext)
    }
}

trait SimpleSecurity: CloudSecurity {}

pub struct MSmartHomeCloudSecurity {}

impl MSmartHomeCloudSecurity {
    const LOGIN_KEY: &'static [u8] = b"ac21b9f9cbfe4ca5a88562ef25e2b768";
    const APP_KEY: &'static [u8] = b"ac21b9f9cbfe4ca5a88562ef25e2b768";
    const IOT_KEY: &'static [u8] = b"6d6569636c6f7564";
    const HMAC_KEY: &'static [u8] = b"50524f445f566e6f436c4a493961696b5338647979";

    pub fn new() -> Self {
        Self {}
    }
}

impl CloudSecurity for MSmartHomeCloudSecurity {
    fn get_iot_key(&self) -> &[u8] {
        Self::IOT_KEY
    }

    fn get_hmac_key(&self) -> &[u8] {
        Self::HMAC_KEY
    }

    fn get_login_key(&self) -> &[u8] {
        Self::LOGIN_KEY
    }
}

impl ProxiedSecurity for MSmartHomeCloudSecurity {
    fn get_app_key(&self) -> &[u8] {
        Self::APP_KEY
    }

    fn encrypt_iam_password(&self, _login_id: &str, password: &str) -> String {
        let m1 = Md5::digest(password);
        let m2 = Md5::digest(m1);

        hex_encode(&m2)
    }
}
