use getifs::{interfaces, MacAddr};
use md5::{Digest, Md5};
use reqwest::blocking::get;
use std::io;
use std::net::Ipv4Addr;
use std::str::FromStr;
pub fn md5_hash(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
pub fn validate_mac(mac: &str) -> bool {
    if mac.len() != 14 || !mac.starts_with("0x") {
        return false;
    }
    mac[2..].chars().all(|c| c.is_ascii_hexdigit())
}
pub fn get_ip_by_mac(mac_str: &str) -> Result<Ipv4Addr, io::Error> {
    let mac = MacAddr::from_str(mac_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    for interface in interfaces()? {
        if let Some(mac_addr) = interface.mac_addr() {
            if mac_addr == mac {
                let addrs = interface.ipv4_addrs()?;
                if let Some(addr) = addrs.iter().find(|a| a.to_string().starts_with("49")) {
                    return Ok(addr.addr());
                }
                if let Some(addr) = addrs.first() {
                    return Ok(addr.addr());
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "No IP found for the given MAC address",
    ))
}
pub fn test_net_connection() -> bool {
    get("https://www.baidu.com").is_ok()
}

use tinycrypt::CryptographyError;

pub fn encrypt(password: &str, key: &str) -> String {
    let encrypted_data = tinycrypt::encrypt(password.as_bytes(), key.as_bytes()).unwrap();
    base64::encode(encrypted_data)
}

pub fn decrypt(password_encrypted: &str, key: &str) -> Option<String> {
    let encrypted_data = base64::decode(password_encrypted).ok()?;
    match tinycrypt::decrypt(&encrypted_data, key.as_bytes()) {
        Ok(decrypted_data) => Some(String::from_utf8(decrypted_data).ok()?),
        Err(CryptographyError::IncorrectPassword) => None,
        Err(_) => None,
    }
}
pub fn fingerprint() -> String {
    machine_uid::get().unwrap_or("Error".to_string())
}
