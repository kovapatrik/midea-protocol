use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use base16ct::lower::encode_string as hex_encode;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::Result;

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

trait CloudSecurity {
    fn get_iot_key(&self) -> Bytes;
    fn get_hmac_key(&self) -> Bytes;
    fn get_login_key(&self) -> Bytes;

    /// Generate a HMAC signature for the provided data and random data. Returns a hex encoded string.
    fn sign(&self, data: Bytes, random_data: Bytes) -> Result<String> {
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
    fn get_app_key(&self) -> Bytes;

    fn encrypt_iam_password(&self, login_id: &str, password: &str) -> String;

    fn get_app_key_and_iv(&self) -> (Bytes, Bytes) {
        let hash = Sha256::digest(self.get_app_key());
        (
            Bytes::copy_from_slice(&hash[0..16]),
            Bytes::copy_from_slice(&hash[16..32]),
        )
    }

    fn encrypt_aes_app_key(&self, data: Bytes) -> Result<Bytes> {
        let (app_key, iv) = self.get_app_key_and_iv();

        let ciphertext = Aes128CbcEnc::new(app_key.as_ref().into(), iv.as_ref().into())
            .encrypt_padded_vec_mut::<Pkcs7>(&data);

        Ok(Bytes::from(ciphertext))
    }

    // fn decr
}
