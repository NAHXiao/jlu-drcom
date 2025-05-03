pub enum Error{
    CreateSockError,
    ChallengeError,
    LoginError,
    AliveError,
    TestNetConnectionError,
    LogoutError,
    LogoutSuccess,
}
// const SERVER_ADDR
// const SERVER_PORT

/// 错误发生后自动重试,连续三次返回Error
pub fn login_and_keep() -> Error{
    
}


struct RuntimeData{
    challenge_send_data,
    challenge_recv_data,
    user_info,
    alive_data,
}
fn set_challenge_data();
fn challenge(); 

fn set_login_data();
fn login();

fn set_keep_alive_data();
fn keep_alive();


