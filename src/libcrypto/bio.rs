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

use std::io::{Read, Write};
use std::fs::{File, OpenOptions};
use std::io::Cursor;

#[doc(hidden)]
pub(self) const MAGIC_SIZE: usize = 4;

#[derive(Debug)]
enum BioType {
    File,
    Mem,
    Socket,
}

#[allow(non_camel_case_types)]
pub struct MEASLINK_BIO_METHOD<R: Read, W: Write> {
    magic: [u8; MAGIC_SIZE],
    reader: Box<R>,
    writer: Box<W>,
    bio_type: BioType,
}

impl<R, W> MEASLINK_BIO_METHOD<R, W>