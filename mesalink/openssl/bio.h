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

#ifndef MESALINK_OPENSSL_BIO_H
#define MESALINK_OPENSSL_BIO_H

#include <mesalink/bio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BIO_METHOD MESALINK_BIO_METHOD
#define BIO MESALINK_BIO

#define BIO_new mesalink_BIO_new
#define BIO_free mesalink_BIO_free

#define BIO_read mesalink_BIO_read
#define BIO_gets mesalink_BIO_gets
#define BIO_write mesalink_BIO_write
#define BIO_puts mesalink_BIO_puts

#define BIO_s_file mesalink_BIO_s_file
#define BIO_new_fp mesalink_BIO_new_fp
#define BIO_set_fp mesalink_BIO_set_fp
#define BIO_get_close mesalink_BIO_get_close
#define BIO_set_close mesalink_BIO_set_close

#define BIO_new_file mesalink_BIO_new_file
#define BIO_read_filename mesalink_BIO_read_filename
#define BIO_write_filename mesalink_BIO_write_filename
#define BIO_append_filename mesalink_BIO_append_filename
#define BIO_rw_filename mesalink_BIO_rw_filename

#define BIO_s_mem mesalink_BIO_s_mem
#define BIO_new_mem_buf mesalink_BIO_new_mem_buf

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_OPENSSL_BIO_H */