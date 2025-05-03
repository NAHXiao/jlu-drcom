use crate::config::Config;
use crate::util::{decrypt, fingerprint, get_ip_by_mac, mac2u64, test_net_connection};
use log::info;
use md5::{Digest, Md5};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use thiserror::Error;
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to create socket")]
    CreateSockError(#[source] std::io::Error),

    #[error("Challenge phase failed")]
    ChallengeError,

    #[error("Login failed, check your credentials")]
    LoginError,

    #[error("Keep alive failed after retry")]
    AliveError,

    #[error("Network connectivity test failed")]
    TestNetConnectionError,

    #[error("Logout operation failed")]
    LogoutError,

    #[error("Logout success")]
    LogoutSuccess,

    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Timeout Error")]
    TimeoutError,
}

const SEND_DATA_SIZE: usize = 1000;
const CHALLENGE_TRY: u8 = 10;
const LOGIN_TRY: u8 = 5;
const ALIVE_TRY: u8 = 5;

struct RuntimeData {
    challenge_send_data: [u8; 20],
    challenge_recv_data: [u8; 1000],
    login_data: [u8; SEND_DATA_SIZE],
    alive_data: [u8; SEND_DATA_SIZE],
    logout_data: [u8; SEND_DATA_SIZE],
    login_salt: [u8; 4],
    tail: [u8; 4],
    socket: UdpSocket,
    server_addr: SocketAddr,
}
use once_cell::sync::OnceCell;
static CTRLC_SET: OnceCell<bool> = OnceCell::new();
pub fn login_and_keep(config: &Config) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    if !*CTRLC_SET.get().unwrap_or(&false) {
        if let Err(e) = ctrlc::set_handler(move || {
            info!("[drcom-signal]: received signal, will logout and exit");
            println!("[drcom-signal]: received signal, will logout and exit");
            r.store(false, Ordering::SeqCst);
            if let Err(e) = CTRLC_SET.set(true) {
                info!("Error setting CTRLC_SET to true : {}", e);
            }
        }) {
            info!("Error setting Ctrl-C handler : {}", e);
        }
    }
    let mac_bytes = config.mac;
    let ip_address = get_ip_by_mac(mac_bytes)?;
    info!("[drcom-bindip]: bind to ip: {:?}", ip_address);
    let socket = create_socket(&ip_address)?;
    let server_addr: SocketAddr = format!("{}:{}", config.server_addr, config.server_port)
        .parse()
        .map_err(|_| {
            Error::CreateSockError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid server address",
            ))
        })?;
    let mut runtime_data = RuntimeData {
        challenge_send_data: [0; 20],
        challenge_recv_data: [0; 1000],
        login_data: [0; SEND_DATA_SIZE],
        alive_data: [0; SEND_DATA_SIZE],
        logout_data: [0; SEND_DATA_SIZE],
        login_salt: [0; 4],
        tail: [0; 4],
        socket,
        server_addr,
    };
    challenge(&mut runtime_data)?;
    runtime_data
        .login_salt
        .copy_from_slice(&runtime_data.challenge_recv_data[4..8]);
    set_login_data(&mut runtime_data, config, mac_bytes)?;
    login(&mut runtime_data)?;
    let mut alive_count = 0;
    let mut alive_fail_count = 0;
    let random = rand::random::<u16>();
    while running.load(Ordering::SeqCst) {
        let alive_data_len = if alive_count > 0 { 40 } else { 42 };
        set_alive_data(&mut runtime_data, alive_count, random)?;
        match send_alive_data(&mut runtime_data, alive_data_len) {
            Ok(_) => {
                alive_fail_count = 0;
            }
            Err(_) => {
                alive_fail_count += 1;
                if alive_fail_count > ALIVE_TRY {
                    return Err(Error::AliveError);
                }
                continue;
            }
        }
        match receive_alive_response(&mut runtime_data) {
            Ok(_) => {
                alive_fail_count = 0;
                if alive_count > 1 {
                    runtime_data
                        .tail
                        .copy_from_slice(&runtime_data.challenge_recv_data[16..20]);
                }
                info!("[drcom-keep-alive]: keep alive.");
            }
            Err(_) => {
                alive_fail_count += 1;
                if alive_fail_count > ALIVE_TRY {
                    return Err(Error::AliveError);
                }
                continue;
            }
        }
        alive_count = (alive_count + 1) % 3;
        for _ in 0..15 {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        if running.load(Ordering::SeqCst) && !test_net_connection() {
            return Err(Error::TestNetConnectionError);
        }
    }
    set_logout_data(&mut runtime_data)?;
    logout(&mut runtime_data)?;
    Ok(())
}
fn create_socket(ip_address: &Ipv4Addr) -> Result<UdpSocket> {
    let socket = UdpSocket::bind((*ip_address, 0)).map_err(Error::CreateSockError)?;
    // timeouts
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(Error::CreateSockError)?;

    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(Error::CreateSockError)?;

    Ok(socket)
}

fn set_challenge_data(data: &mut [u8], try_count: u8) {
    data.fill(0);

    let random = rand::random::<u16>();
    data[0] = 0x01;
    data[1] = 0x02 + try_count;
    data[2] = (random & 0xFF) as u8;
    data[3] = ((random >> 8) & 0xFF) as u8;
    data[4] = 0x09;
}
fn challenge(runtime_data: &mut RuntimeData) -> Result<()> {
    let mut try_count = 0;

    loop {
        if try_count >= CHALLENGE_TRY {
            return Err(Error::ChallengeError);
        }
        set_challenge_data(&mut runtime_data.challenge_send_data, try_count);
        try_count += 1;
        runtime_data
            .socket
            .send_to(
                &runtime_data.challenge_send_data[..20],
                runtime_data.server_addr,
            )
            .map_err(|_| Error::ChallengeError)?;
        let result = runtime_data
            .socket
            .recv_from(&mut runtime_data.challenge_recv_data);

        match result {
            Ok((len, _)) => {
                if len > 0 && runtime_data.challenge_recv_data[0] == 0x02 {
                    info!("[drcom-challenge]: challenge success!");
                    return Ok(());
                }

                if len > 0 && runtime_data.challenge_recv_data[0] == 0x07 {
                    return Err(Error::ChallengeError);
                }

                info!("[drcom-challenge]: challenge failed!, try again.");
            }
            Err(_) => {
                info!("[drcom-challenge]: receive data from server failed.");
            }
        }
    }
}
fn set_login_data(
    runtime_data: &mut RuntimeData,
    config: &Config,
    mac_bytes: [u8; 6],
) -> Result<()> {
    runtime_data.login_data.fill(0);
    let username = config.username.as_bytes();
    let password = decrypt(&config.password_enctypted, &fingerprint()).unwrap();
    let hostname = config.hostname.as_bytes();
    let os_name = config.os_name.as_bytes();
    let mut data_index = 0;
    // Magic 3 bytes, username_len 1 byte
    runtime_data.login_data[data_index] = 0x03;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x01;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x00;
    data_index += 1;
    runtime_data.login_data[data_index] = (username.len() + 20) as u8;
    data_index += 1;
    // MD5 of 0x03 0x01 salt password
    let mut hasher = Md5::new();
    hasher.update(&[0x03, 0x01]);
    hasher.update(&runtime_data.login_salt);
    hasher.update(&password);
    let md5_result = hasher.finalize();
    runtime_data.login_data[data_index..data_index + 16].copy_from_slice(&md5_result[..]);
    data_index += 16;
    // Username (36 bytes padded)
    runtime_data.login_data[data_index..data_index + username.len()].copy_from_slice(&username[..]);
    data_index += username.len().max(36);
    // 0x00 0x00
    data_index += 2;
    // MAC XOR with md5[0:6]
    let mut sum: u64 = 0;
    for i in 0..6 {
        sum = (md5_result[i] as u64) + sum * 256;
    }
    let mac_val = mac2u64(mac_bytes);
    sum ^= mac_val;
    // Copy MAC XOR result
    for i in (0..6).rev() {
        runtime_data.login_data[data_index + i] = (sum % 256) as u8;
        sum /= 256;
    }
    data_index += 6;

    // MD5 of 0x01 pwd salt 0x00 0x00 0x00 0x00
    let mut hasher = Md5::new();
    hasher.update(&[0x01]);
    hasher.update(&password);
    hasher.update(&runtime_data.login_salt);
    hasher.update(&[0x00, 0x00, 0x00, 0x00]);
    let md5_result = hasher.finalize();
    // Copy MD5 result
    runtime_data.login_data[data_index..data_index + 16].copy_from_slice(&md5_result[..]);
    data_index += 16;

    // 0x01 0x31 0x8c 0x21 0x28 0x00*12
    runtime_data.login_data[data_index] = 0x01;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x31;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x8c;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x21;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x28;
    data_index += 1;
    data_index += 12; // Skip 12 bytes (already filled with 0x00)

    // MD5 of login_data[0-data_index] 0x14 0x00 0x07 0x0b
    let mut hasher = Md5::new();
    hasher.update(&runtime_data.login_data[0..data_index]);
    hasher.update(&[0x14, 0x00, 0x07, 0x0b]);
    let md5_result = hasher.finalize();
    // Copy first 8 bytes of MD5 result
    runtime_data.login_data[data_index..data_index + 8].copy_from_slice(&md5_result[0..8]);
    data_index += 8;

    // 0x01 0x00*4
    runtime_data.login_data[data_index] = 0x01;
    data_index += 1;
    data_index += 4; // Skip 4 bytes (already filled with 0x00)

    // Hostname (71 bytes padded)
    let hostname_len = hostname.len().min(71);
    runtime_data.login_data[data_index..data_index + hostname_len]
        .copy_from_slice(&hostname[0..hostname_len]);
    data_index += 71;

    // 0x01
    runtime_data.login_data[data_index] = 0x01;
    data_index += 1;

    // OS name (128 bytes padded)
    let os_name_len = os_name.len().min(128);
    runtime_data.login_data[data_index..data_index + os_name_len]
        .copy_from_slice(&os_name[0..os_name_len]);
    data_index += 128;

    // 0x6d 0x00 0x00 password_len
    runtime_data.login_data[data_index] = 0x6d;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x00;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x00;
    data_index += 1;
    runtime_data.login_data[data_index] = password.len() as u8;
    data_index += 1;

    // ROR (MD5 of 0x03 0x01 salt pass) pass
    let mut hasher = Md5::new();
    hasher.update(&[0x03, 0x01]);
    hasher.update(&runtime_data.login_salt);
    hasher.update(&password);
    let md5_result = hasher.finalize();

    // Convert password from &str to bytes for indexing
    let password_bytes = password.as_bytes();
    for i in 0..password_bytes.len() {
        let ror_check = md5_result[i] ^ password_bytes[i];
        // ROR: (ror_check << 3) & 0xFF + (ror_check >> 5)
        runtime_data.login_data[data_index] = ((ror_check << 3) & 0xFF) + (ror_check >> 5);
        data_index += 1;
    }

    // 0x02 0x0c
    runtime_data.login_data[data_index] = 0x02;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x0c;
    data_index += 1;

    // Checksum point
    let check_point = data_index;
    runtime_data.login_data[data_index] = 0x01;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x26;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x07;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x11;
    data_index += 1;

    // 0x00 0x00 MAC
    runtime_data.login_data[data_index] = 0x00;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x00;
    data_index += 1;

    for i in 0..6 {
        runtime_data.login_data[data_index + i] = ((mac_val >> (i * 8)) & 0xFF) as u8;
    }
    data_index += 6;

    // 0x00 0x00 0x00 0x00
    runtime_data.login_data[data_index] = 0x00;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x00;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x00;
    data_index += 1;
    runtime_data.login_data[data_index] = 0x00;
    data_index += 1;

    // Checksum
    let mut sum: u64 = 1234;
    for i in (0..data_index).step_by(4) {
        let mut check: u64 = 0;
        for j in 0..4 {
            if i + j < data_index {
                check = check * 256 + runtime_data.login_data[i + j] as u64;
            }
        }
        sum ^= check;
    }
    sum = (1968 * sum) & 0xFFFFFFFF;

    for j in 0..4 {
        runtime_data.login_data[check_point + j] = ((sum >> (j * 8)) & 0xFF) as u8;
    }

    Ok(())
}
fn login(runtime_data: &mut RuntimeData) -> Result<()> {
    let mut try_count = 0;

    loop {
        if try_count >= LOGIN_TRY {
            return Err(Error::LoginError);
        }

        try_count += 1;
        runtime_data
            .socket
            .send_to(&runtime_data.login_data[..338], runtime_data.server_addr)
            .map_err(|_| Error::LoginError)?;
        let result = runtime_data
            .socket
            .recv_from(&mut runtime_data.challenge_recv_data);

        match result {
            Ok((len, _)) => {
                if len > 0 && runtime_data.challenge_recv_data[0] == 0x04 {
                    info!("[drcom-login]: login success!");
                    return Ok(());
                }

                if len > 0 && runtime_data.challenge_recv_data[0] == 0x05 {
                    info!("[drcom-login]: wrong password or username!");
                    return Err(Error::LoginError);
                }

                info!("[drcom-login]: login failed!, try again.");
            }
            Err(_) => {
                info!("[drcom-login]: receive data from server failed.");
            }
        }
    }
}

/// Sets the alive data
fn set_alive_data(runtime_data: &mut RuntimeData, alive_count: u8, random: u16) -> Result<()> {
    // Reset alive data
    runtime_data.alive_data.fill(0);

    // Set alive data based on alive count
    runtime_data.alive_data[0] = 0x07;
    runtime_data.alive_data[1] = alive_count;
    runtime_data.alive_data[2] = 0x28;
    runtime_data.alive_data[3] = 0x00;
    runtime_data.alive_data[4] = 0x0b;
    runtime_data.alive_data[5] = alive_count * 2 + 1;
    runtime_data.alive_data[6] = 0xdc;
    runtime_data.alive_data[7] = 0x02;

    // Add random value
    let new_random = random + rand::random::<u16>() % 10;
    runtime_data.alive_data[8] = (new_random & 0xFF) as u8;
    runtime_data.alive_data[9] = ((new_random >> 8) & 0xFF) as u8;

    // Copy tail
    runtime_data.alive_data[16..20].copy_from_slice(&runtime_data.tail);

    Ok(())
}

/// Sends alive data
fn send_alive_data(runtime_data: &mut RuntimeData, alive_data_len: usize) -> Result<()> {
    runtime_data
        .socket
        .send_to(
            &runtime_data.alive_data[..alive_data_len],
            runtime_data.server_addr,
        )
        .map_err(|_| Error::AliveError)?;

    Ok(())
}

/// Receives alive response
fn receive_alive_response(runtime_data: &mut RuntimeData) -> Result<()> {
    runtime_data.challenge_recv_data.fill(0);

    let result = runtime_data
        .socket
        .recv_from(&mut runtime_data.challenge_recv_data);

    match result {
        Ok((len, _)) => {
            if len > 0 && runtime_data.challenge_recv_data[0] == 0x07 {
                return Ok(());
            }

            Err(Error::AliveError)
        }
        Err(_) => {
            info!("[drcom-keep-alive]: receive keep-alive response data from server failed.");
            Err(Error::AliveError)
        }
    }
}
fn set_logout_data(runtime_data: &mut RuntimeData) -> Result<()> {
    runtime_data.logout_data.fill(0);
    runtime_data.logout_data[0] = 0x06;
    runtime_data.logout_data[1] = 0x01;
    runtime_data.logout_data[2] = 0x00;
    runtime_data.logout_data[3] = 0x00;

    Ok(())
}
fn logout(runtime_data: &mut RuntimeData) -> Result<()> {
    runtime_data
        .socket
        .send_to(&runtime_data.logout_data[..80], runtime_data.server_addr)
        .map_err(|_| Error::LogoutError)?;
    let result = runtime_data
        .socket
        .recv_from(&mut runtime_data.challenge_recv_data);

    match result {
        Ok((len, _)) => {
            if len > 0 {
                info!("[drcom-logout]: logout success!");
                return Ok(());
            }

            Err(Error::LogoutError)
        }
        Err(_) => {
            info!("[drcom-logout]: receive logout response data from server failed.");
            Err(Error::LogoutError)
        }
    }
}
