use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
#[cfg(target_os = "linux")]
fn test_should_start() {
    let mut child = Command::new("mosquitto")
        .args(&["-c", "tests/mosquitto_valid.conf"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_secs(3));

    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    thread::sleep(Duration::from_secs(3));
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
