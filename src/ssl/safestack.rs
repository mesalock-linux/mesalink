/*
 *   __  __                 _     _       _
 *  |  \/  | ___  ___  __ _| |   (_)_ __ | | __
 *  | |\/| |/ _ \/ __|/ _` | |   | | '_ \| |/ /
 *  | |  | |  __/\__ \ (_| | |___| | | | |   <
 *  |_|  |_|\___||___/\__,_|_____|_|_| |_|_|\_\
 *
 * Copyright (c) 2017-2018, The MesaLink Authors.
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

use libc::c_int;
use ssl::err::{MesalinkBuiltinError, MesalinkInnerResult};
use ssl::error_san::*;
use ssl::x509::{MESALINK_X509, MESALINK_X509_NAME};
use ssl::{MesalinkOpaquePointerType, MAGIC, MAGIC_SIZE};
use ssl::{SSL_FAILURE, SSL_SUCCESS};
use std::ptr;

// ---------------------------------------
// STACK for MESALINK_X509
// ---------------------------------------

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct MESALINK_STACK_MESALINK_X509 {
    magic: [u8; MAGIC_SIZE],
    pub stack: Vec<MESALINK_X509>,
}

impl MesalinkOpaquePointerType for MESALINK_STACK_MESALINK_X509 {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl MESALINK_STACK_MESALINK_X509 {
    pub(crate) fn new(names: Vec<MESALINK_X509>) -> MESALINK_STACK_MESALINK_X509 {
        MESALINK_STACK_MESALINK_X509 {
            magic: *MAGIC,
            stack: names,
        }
    }
}

#[no_mangle]
pub extern "C" fn mesalink_sk_X509_new_null() -> *mut MESALINK_STACK_MESALINK_X509 {
    let stack = MESALINK_STACK_MESALINK_X509::new(vec![]);
    Box::into_raw(Box::new(stack)) as *mut MESALINK_STACK_MESALINK_X509
}

#[no_mangle]
pub extern "C" fn mesalink_sk_X509_num(stack_ptr: *const MESALINK_STACK_MESALINK_X509) -> c_int {
    check_inner_result!(inner_mesalink_sk_X509_num(stack_ptr), SSL_FAILURE)
}

#[allow(non_snake_case)]
fn inner_mesalink_sk_X509_num(
    stack_ptr: *const MESALINK_STACK_MESALINK_X509,
) -> MesalinkInnerResult<c_int> {
    let stack = sanitize_const_ptr_for_ref(stack_ptr)?;
    Ok(stack.stack.len() as c_int)
}

#[no_mangle]
pub extern "C" fn mesalink_sk_X509_value(
    stack_ptr: *const MESALINK_STACK_MESALINK_X509,
    index: c_int,
) -> *const MESALINK_X509 {
    check_inner_result!(inner_mesalink_sk_X509_value(stack_ptr, index), ptr::null())
}

#[allow(non_snake_case)]
fn inner_mesalink_sk_X509_value(
    stack_ptr: *const MESALINK_STACK_MESALINK_X509,
    index: c_int,
) -> MesalinkInnerResult<*const MESALINK_X509> {
    let stack = sanitize_const_ptr_for_ref(stack_ptr)?;
    let item = stack
        .stack
        .get(index as usize)
        .ok_or(error!(MesalinkBuiltinError::ErrorBadFuncArg.into()))?;
    Ok(item as *const MESALINK_X509)
}

#[no_mangle]
pub extern "C" fn mesalink_sk_X509_push(
    stack_ptr: *mut MESALINK_STACK_MESALINK_X509,
    item_ptr: *const MESALINK_X509,
) -> c_int {
    check_inner_result!(
        inner_mesalink_sk_X509_push(stack_ptr, item_ptr),
        SSL_FAILURE
    )
}

#[allow(non_snake_case)]
fn inner_mesalink_sk_X509_push(
    stack_ptr: *mut MESALINK_STACK_MESALINK_X509,
    item_ptr: *const MESALINK_X509,
) -> MesalinkInnerResult<c_int> {
    let stack = sanitize_ptr_for_mut_ref(stack_ptr)?;
    let item = sanitize_const_ptr_for_ref(item_ptr)?;
    stack.stack.push(item.clone());
    Ok(SSL_SUCCESS)
}

#[no_mangle]
pub extern "C" fn mesalink_sk_X509_free(stack_ptr: *mut MESALINK_STACK_MESALINK_X509) {
    let _ = check_inner_result!(inner_mesalink_sk_X509_free(stack_ptr), SSL_FAILURE);
}

#[allow(non_snake_case)]
fn inner_mesalink_sk_X509_free(
    stack_ptr: *mut MESALINK_STACK_MESALINK_X509,
) -> MesalinkInnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(stack_ptr)?;
    let _ = unsafe { Box::from_raw(stack_ptr) };
    Ok(SSL_SUCCESS)
}

// ---------------------------------------
// STACK for MESALINK_X509_NAME
// ---------------------------------------

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct MESALINK_STACK_MESALINK_X509_NAME {
    magic: [u8; MAGIC_SIZE],
    pub stack: Vec<MESALINK_X509_NAME>,
}

impl MesalinkOpaquePointerType for MESALINK_STACK_MESALINK_X509_NAME {
    fn check_magic(&self) -> bool {
        self.magic == *MAGIC
    }
}

impl MESALINK_STACK_MESALINK_X509_NAME {
    pub fn new(names: Vec<MESALINK_X509_NAME>) -> MESALINK_STACK_MESALINK_X509_NAME {
        MESALINK_STACK_MESALINK_X509_NAME {
            magic: *MAGIC,
            stack: names,
        }
    }
}

#[no_mangle]
pub extern "C" fn mesalink_sk_X509_NAME_new_null() -> *mut MESALINK_STACK_MESALINK_X509_NAME {
    let stack = MESALINK_STACK_MESALINK_X509_NAME::new(vec![]);
    Box::into_raw(Box::new(stack)) as *mut MESALINK_STACK_MESALINK_X509_NAME
}

#[no_mangle]
pub extern "C" fn mesalink_sk_X509_NAME_num(
    stack_ptr: *const MESALINK_STACK_MESALINK_X509_NAME,
) -> c_int {
    check_inner_result!(inner_mesalink_sk_X509_NAME_num(stack_ptr), SSL_FAILURE)
}

#[allow(non_snake_case)]
fn inner_mesalink_sk_X509_NAME_num(
    stack_ptr: *const MESALINK_STACK_MESALINK_X509_NAME,
) -> MesalinkInnerResult<c_int> {
    let stack = sanitize_const_ptr_for_ref(stack_ptr)?;
    Ok(stack.stack.len() as c_int)
}

#[no_mangle]
pub extern "C" fn mesalink_sk_X509_NAME_value(
    stack_ptr: *const MESALINK_STACK_MESALINK_X509_NAME,
    index: c_int,
) -> *const MESALINK_X509_NAME {
    check_inner_result!(
        inner_mesalink_sk_X509_NAME_value(stack_ptr, index),
        ptr::null()
    )
}

#[allow(non_snake_case)]
fn inner_mesalink_sk_X509_NAME_value(
    stack_ptr: *const MESALINK_STACK_MESALINK_X509_NAME,
    index: c_int,
) -> MesalinkInnerResult<*const MESALINK_X509_NAME> {
    let stack = sanitize_const_ptr_for_ref(stack_ptr)?;
    let item = stack
        .stack
        .get(index as usize)
        .ok_or(error!(MesalinkBuiltinError::ErrorBadFuncArg.into()))?;
    Ok(item as *const MESALINK_X509_NAME)
}

#[no_mangle]
pub extern "C" fn mesalink_sk_X509_NAME_push(
    stack_ptr: *mut MESALINK_STACK_MESALINK_X509_NAME,
    item_ptr: *const MESALINK_X509_NAME,
) -> c_int {
    check_inner_result!(
        inner_mesalink_sk_X509_NAME_push(stack_ptr, item_ptr),
        SSL_FAILURE
    )
}

#[allow(non_snake_case)]
fn inner_mesalink_sk_X509_NAME_push(
    stack_ptr: *mut MESALINK_STACK_MESALINK_X509_NAME,
    item_ptr: *const MESALINK_X509_NAME,
) -> MesalinkInnerResult<c_int> {
    let stack = sanitize_ptr_for_mut_ref(stack_ptr)?;
    let item = sanitize_const_ptr_for_ref(item_ptr)?;
    stack.stack.push(item.clone());
    Ok(SSL_SUCCESS)
}

#[no_mangle]
pub extern "C" fn mesalink_sk_X509_NAME_free(stack_ptr: *mut MESALINK_STACK_MESALINK_X509_NAME) {
    let _ = check_inner_result!(inner_mesalink_sk_X509_NAME_free(stack_ptr), SSL_FAILURE);
}

#[allow(non_snake_case)]
fn inner_mesalink_sk_X509_NAME_free(
    stack_ptr: *mut MESALINK_STACK_MESALINK_X509_NAME,
) -> MesalinkInnerResult<c_int> {
    let _ = sanitize_ptr_for_mut_ref(stack_ptr)?;
    let _ = unsafe { Box::from_raw(stack_ptr) };
    Ok(SSL_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::internal::pemfile;
    use ssl::x509::{MESALINK_X509, MESALINK_X509_NAME};
    use ssl::SSL_SUCCESS;
    use std::fs::File;
    use std::io::BufReader;

    #[test]
    fn x509_sk() {
        let stack_ptr: *mut MESALINK_STACK_MESALINK_X509 = mesalink_sk_X509_new_null();
        let mut certs_io = BufReader::new(File::open("tests/test.certs").unwrap());
        let certs = pemfile::certs(&mut certs_io).unwrap();
        let certs_count = certs.len();
        assert_eq!(true, certs_count > 0);
        for cert in certs.into_iter() {
            let x509 = MESALINK_X509::new(cert);
            let x509_ptr = Box::into_raw(Box::new(x509)) as *mut MESALINK_X509;
            assert_eq!(SSL_SUCCESS, mesalink_sk_X509_push(stack_ptr, x509_ptr));
            let _ = unsafe { Box::from_raw(x509_ptr) }; // push() clones the X509 object
        }
        assert_eq!(certs_count as c_int, mesalink_sk_X509_num(stack_ptr));
        for index in 0..certs_count {
            let x509_ptr = mesalink_sk_X509_value(stack_ptr, index as c_int);
            assert_ne!(x509_ptr, ptr::null_mut());
        }
        mesalink_sk_X509_free(stack_ptr);
    }

    #[test]
    fn x509_name_sk() {
        let stack_ptr: *mut MESALINK_STACK_MESALINK_X509_NAME = mesalink_sk_X509_NAME_new_null();
        let names = ["*.google.com", "youtube.com", "map.google.com"];
        for name in names.into_iter() {
            let x509_name = MESALINK_X509_NAME::new(name.as_bytes());
            let x509_name_ptr = Box::into_raw(Box::new(x509_name)) as *mut MESALINK_X509_NAME;
            assert_eq!(
                SSL_SUCCESS,
                mesalink_sk_X509_NAME_push(stack_ptr, x509_name_ptr)
            );
            let _ = unsafe { Box::from_raw(x509_name_ptr) }; // push() clones the X509_NAME object
        }
        assert_eq!(names.len() as c_int, mesalink_sk_X509_NAME_num(stack_ptr));
        for index in 0..names.len() {
            let x509_name_ptr = mesalink_sk_X509_NAME_value(stack_ptr, index as c_int);
            assert_ne!(x509_name_ptr, ptr::null_mut());
        }
        mesalink_sk_X509_NAME_free(stack_ptr);
    }

    #[test]
    fn sk_free_null_pointer() {
        mesalink_sk_X509_free(ptr::null_mut());
        mesalink_sk_X509_NAME_free(ptr::null_mut());
    }
}
