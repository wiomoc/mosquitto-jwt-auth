use std::os::raw::{c_char, c_int, c_long, c_void};

use crate::MosquittoJWTAuthPluginInstance;
use std::ffi::CStr;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mosquitto {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mosquitto_opt {
    pub key: *mut c_char,
    pub value: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mosquitto_auth_opt {
    pub _key: *mut c_char,
    pub _value: *mut c_char,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mosquitto_acl_msg {
    pub topic: *const c_char,
    pub _payload: *const c_void,
    pub _payloadlen: c_long,
    pub _qos: c_int,
    pub _retain: bool,
}

const MOSQ_AUTH_PLUGIN_VERSION: c_int = 4;

const MOSQ_ERR_SUCCESS: c_int = 0;
const MOSQ_ERR_UNKNOWN: c_int = 1;
const MOSQ_ERR_AUTH: c_int = 11;
const MOSQ_ERR_ACL_DENIED: c_int = 12;
const MOSQ_ERR_PLUGIN_DEFER: c_int = 17;

const MOSQ_ACL_READ: c_int = 1;
const MOSQ_ACL_WRITE: c_int = 2;
const MOSQ_ACL_SUBSCRIBE: c_int = 4;

pub(crate) enum AclType {
    Publish,
    Subscribe,
}

pub(crate) type ClientID = *mut mosquitto;

#[no_mangle]
pub extern "C" fn mosquitto_auth_plugin_version() -> c_int {
    MOSQ_AUTH_PLUGIN_VERSION
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn mosquitto_auth_plugin_init(
    user_data: *mut *mut c_void,
    _opts: *mut mosquitto_opt,
    _opt_count: c_int,
) -> c_int {
    let instance = MosquittoJWTAuthPluginInstance::new();

    unsafe {
        *user_data = Box::into_raw(Box::new(instance)) as *mut c_void;
    }

    MOSQ_ERR_SUCCESS
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn mosquitto_auth_plugin_cleanup(
    user_data: *mut c_void,
    _opts: *mut mosquitto_opt,
    _opt_count: c_int,
) -> c_int {
    unsafe {
        Box::from_raw(user_data as *mut MosquittoJWTAuthPluginInstance);
    }

    MOSQ_ERR_SUCCESS
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn mosquitto_auth_security_init(
    user_data: *mut c_void,
    opts: *mut mosquitto_opt,
    opt_count: c_int,
    _reload: bool,
) -> c_int {
    let opts = unsafe { std::slice::from_raw_parts(opts, opt_count as usize) }
        .iter()
        .map(|option| {
            (
                unsafe { CStr::from_ptr(option.key) }.to_str().unwrap(),
                unsafe { CStr::from_ptr(option.value) }.to_str().unwrap(),
            )
        })
        .collect();

    let instance = unsafe { &mut *(user_data as *mut MosquittoJWTAuthPluginInstance) };

    let result = instance.setup(opts);

    match result {
        Ok(_) => MOSQ_ERR_SUCCESS,
        Err(_) => MOSQ_ERR_UNKNOWN,
    }
}

#[no_mangle]
pub extern "C" fn mosquitto_auth_security_cleanup(
    _user_data: *mut c_void,
    _opts: *mut mosquitto_opt,
    _opt_count: c_int,
    _reload: bool,
) -> c_int {
    MOSQ_ERR_SUCCESS
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn mosquitto_auth_acl_check(
    user_data: *mut c_void,
    access: c_int,
    client: *mut mosquitto,
    msg: *const mosquitto_acl_msg,
) -> c_int {
    let acl_type = match access {
        MOSQ_ACL_WRITE => AclType::Publish,
        MOSQ_ACL_SUBSCRIBE => AclType::Subscribe,
        MOSQ_ACL_READ => return MOSQ_ERR_SUCCESS,
        _ => return MOSQ_ERR_PLUGIN_DEFER,
    };

    let instance = unsafe { &mut *(user_data as *mut MosquittoJWTAuthPluginInstance) };

    let topic = unsafe { CStr::from_ptr((*msg).topic) }.to_str().unwrap();

    let result = instance.acl_check(client, acl_type, topic);

    match result {
        Ok(_) => MOSQ_ERR_SUCCESS,
        Err(_) => MOSQ_ERR_ACL_DENIED,
    }
}

fn option_cstr_from_ptr<'a>(cstr: *const c_char) -> Option<&'a str> {
    if cstr.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(cstr) }.to_str().unwrap())
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn mosquitto_auth_unpwd_check(
    user_data: *mut c_void,
    client: *mut mosquitto,
    username: *const c_char,
    password: *const c_char,
) -> c_int {
    let instance = unsafe { &mut *(user_data as *mut MosquittoJWTAuthPluginInstance) };

    println!("{:?} {:?}", username, password);
    let username = option_cstr_from_ptr(username);
    let password = option_cstr_from_ptr(password);

    let result = instance.authenticate_user(client, username, password);

    match result {
        Ok(_) => MOSQ_ERR_SUCCESS,
        Err(_) => MOSQ_ERR_AUTH,
    }
}

#[no_mangle]
pub extern "C" fn mosquitto_auth_psk_key_get(
    _user_data: *mut c_void,
    _client: *mut mosquitto,
    _hint: *const c_char,
    _identity: *const c_char,
    _key: *mut c_char,
    _max_key_len: c_int,
) -> c_int {
    MOSQ_ERR_PLUGIN_DEFER
}

#[no_mangle]
pub extern "C" fn mosquitto_auth_start(
    _user_data: *mut c_void,
    _client: *mut mosquitto,
    _method: *const c_char,
    _reauth: bool,
    _data_in: *const c_void,
    _data_in_len: u16,
    _data_out: *mut *mut c_void,
    _data_out_len: *mut u16,
) -> c_int {
    MOSQ_ERR_PLUGIN_DEFER
}

#[no_mangle]
pub extern "C" fn mosquitto_auth_continue(
    _user_data: *mut c_void,
    _client: *mut mosquitto,
    _method: *const c_char,
    _data_in: *const c_void,
    _data_in_len: u16,
    _data_out: *mut *mut c_void,
    _data_out_len: *mut u16,
) -> c_int {
    MOSQ_ERR_PLUGIN_DEFER
}
