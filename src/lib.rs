/* lib.rs
 *                            _ _       _
 *                           | (_)     | |
 *  _ __ ___   ___  ___  __ _| |_ _ __ | | __
 * | '_ ` _ \ / _ \/ __|/ _` | | | '_ \| |/ /
 * | | | | | |  __/\__ \ (_| | | | | | |   <
 * |_| |_| |_|\___||___/\__,_|_|_|_| |_|_|\_\
 *
 * Copyright (C) 2017 Baidu USA.
 *
 * This file is part of Mesalink.
 */

#![deny(trivial_numeric_casts, unstable_features, unused_qualifications)]
#![forbid(anonymous_parameters, trivial_casts, unused_extern_crates, unused_import_braces,
          unused_results, variant_size_differences, warnings)]

extern crate libc;
extern crate rustls;
extern crate webpki_roots;

#[cfg(feature = "error_strings")]
#[macro_use] extern crate lazy_static;

pub mod ssl;
