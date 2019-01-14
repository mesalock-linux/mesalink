/*
 *   __  __                 _     _       _
 *  |  \/  | ___  ___  __ _| |   (_)_ __ | | __
 *  | |\/| |/ _ \/ __|/ _` | |   | | '_ \| |/ /
 *  | |  | |  __/\__ \ (_| | |___| | | | |   <
 *  |_|  |_|\___||___/\__,_|_____|_|_| |_|_|\_\
 *
 * Copyright (c) 2017-2019, The MesaLink Authors.
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#[cfg(feature = "error_strings")]
#[doc(hidden)]
#[macro_export]
macro_rules! call_site {
    () => {{
        concat!(file!(), ":", line!())
    }};
}
#[cfg(not(feature = "error_strings"))]
#[doc(hidden)]
#[macro_export]
macro_rules! call_site {
    () => {{
        "call_site information not enabled"
    }};
}
#[doc(hidden)]
#[macro_export]
macro_rules! error {
    ($code:expr) => {{
        use libssl::err::MesalinkError;
        MesalinkError::new($code, call_site!())
    }};
}
// A utility macro that wraps each inner API implementation and checks its
// returned value. This macro also catches panics and prevents unwinding across
// FFI boundaries. Note that the panic mode must be set to `unwind` in
// Cargo.toml.
#[doc(hidden)]
#[macro_export]
macro_rules! check_inner_result {
    ($inner:expr, $err_ret:expr) => {{
        use libssl::err::{ErrorQueue, MesalinkBuiltinError};
        use std::panic;
        match panic::catch_unwind(panic::AssertUnwindSafe(|| $inner))
            .unwrap_or_else(|_| Err(error!(MesalinkBuiltinError::Panic.into())))
        {
            Ok(r) => r,
            Err(e) => {
                ErrorQueue::push_error(e);
                $err_ret
            }
        }
    }};
}
