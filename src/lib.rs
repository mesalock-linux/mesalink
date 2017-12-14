/*
 *   __  __                 _     _       _
 *  |  \/  | ___  ___  __ _| |   (_)_ __ | | __
 *  | |\/| |/ _ \/ __|/ _` | |   | | '_ \| |/ /
 *  | |  | |  __/\__ \ (_| | |___| | | | |   <
 *  |_|  |_|\___||___/\__,_|_____|_|_| |_|_|\_\
 *
 * Copyright (c) 2017, The MesaLink Authors. 
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#![deny(trivial_numeric_casts, unstable_features, unused_qualifications)]
#![forbid(anonymous_parameters, trivial_casts, unused_extern_crates, unused_import_braces,
          unused_results, variant_size_differences, warnings)]

extern crate libc;
extern crate rustls;
extern crate ring;
extern crate webpki;
extern crate webpki_roots;

#[cfg(feature = "error_strings")]
#[macro_use] extern crate lazy_static;

pub mod ssl;
