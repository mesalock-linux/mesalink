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

use libssl::err::{MesalinkBuiltinError, MesalinkInnerResult};
use MesalinkOpaquePointerType;

pub(crate) fn sanitize_const_ptr_for_ref<'a, T>(ptr: *const T) ->MesalinkInnerResult<&'a T>
where
    T: MesalinkOpaquePointerType,
{
    let ptr = ptr as *mut T;
    sanitize_ptr_for_mut_ref(ptr).map(|r| r as &'a T)
}
pub(crate) fn sanitize_ptr_for_ref<'a, T>(ptr: *mut T) -> MesalinkInnerResult<&'a T>
where
    T: MesalinkOpaquePointerType,
{
    sanitize_ptr_for_mut_ref(ptr).map(|r| r as &'a T)
}
pub(crate) fn sanitize_ptr_for_mut_ref<'a, T>(ptr: *mut T) -> MesalinkInnerResult<&'a mut T>
where
    T: MesalinkOpaquePointerType,
{
    if ptr.is_null() {
        return Err(error!(MesalinkBuiltinError::NullPointer.into()));
    }
    let obj_ref: &mut T = unsafe { &mut *ptr };
    if obj_ref.check_magic() {
        Ok(obj_ref)
    } else {
        Err(error!(MesalinkBuiltinError::MalformedObject.into()))
    }
}
