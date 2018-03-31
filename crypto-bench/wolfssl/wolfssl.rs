#![feature(test)]

extern crate test;

#[macro_use]
extern crate crypto_bench;

#[allow(dead_code, non_camel_case_types, non_upper_case_globals, non_snake_case)]
mod ffi;

mod aesgcm;
mod chachapoly;
mod sha;
