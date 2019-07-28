use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
#[cfg(target_os = "linux")]
fn test_valid() {
    let mut child = Command::new("mosquitto")
        .args(&["-c", "tests/mosquitto_valid.conf"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_secs(3));

    assert_eq!(Command::new("mosquitto_pub")
                   .stderr(Stdio::piped())
                   .args(&["-h", "localhost",
                       "-p", "3884",
                       "-u", "name",
                       "-P", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJwdWJsIjpbIi8xMjMiXX0.96H243PnCwTHuXj7To4FbmEeWrSZXlNCAhr80dYKxSQ",
                       "-t", "/123",
                       "-m", "abc"])
                   .output()
                   .unwrap()
                   .stderr[..], b""[..]);

    assert_eq!(Command::new("mosquitto_pub")
                   .stderr(Stdio::piped())
                   .args(&["-h", "localhost",
                       "-p", "3884",
                       "-u", "name",
                       "-P", "eyJgbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMdM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJwdWJsIjpbIi8xMjMiXX0.96H243PnCwTHuXj7To4FbmEeWrSZXlNCAhr80dYKxSl",
                       "-t", "/123",
                       "-m", "abc"])
                   .output()
                   .unwrap()
                   .stderr[..], b"Connection Refused: not authorised.\n"[..]);

    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn test_invalid_config() {
    let mut child = Command::new("mosquitto")
        .args(&["-c", "tests/mosquitto_invalid_alg.conf"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_secs(3));

    assert_eq!(child.wait().unwrap().code().unwrap(), 1);
}
