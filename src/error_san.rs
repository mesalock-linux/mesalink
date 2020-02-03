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

use crate::libssl::err::{MesalinkBuiltinError, MesalinkInnerResult};
use crate::MesalinkOpaquePointerType;

pub(crate) fn sanitize_const_ptr_for_ref<'a, T>(ptr: Option<Box<T>>) -> MesalinkInnerResult<Box<T>>
where
    T: MesalinkOpaquePointerType,
{
    sanitize_ptr_for_mut_ref(ptr)
}
pub(crate) fn sanitize_ptr_for_ref<'a, T>(ptr: Option<Box<T>>) -> MesalinkInnerResult<Box<T>>
where
    T: MesalinkOpaquePointerType,
{
    sanitize_ptr_for_mut_ref(ptr)
}
pub(crate) fn sanitize_ptr_for_mut_ref<'a, T>(ptr: Option<Box<T>>) -> MesalinkInnerResult<Box<T>>
where
    T: MesalinkOpaquePointerType,
{
    match ptr {
        Some(obj) => match obj.check_magic() {
            true => Ok(obj),
            false => Err(error!(MesalinkBuiltinError::MalformedObject.into())),
        },
        None => Err(error!(MesalinkBuiltinError::NullPointer.into())),
    }
}
