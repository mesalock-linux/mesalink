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

use bitflags::bitflags;
use libc::c_long;

bitflags! {
    pub struct SgxConfigFlags: c_long {
        const SGX_FLAGS_DEBUG = 0b0000_0001;
        const SGX_ALLOW_CONFIGURATION_NEEDED = 0b0000_0010;
        const SGX_ALLOW_GROUP_OUT_OF_DATE = 0b0000_0100;
    }
}
