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

#ifdef __cplusplus
extern "C" {
#endif

#define MESALINK_BIO_METHOD BIO_METHOD
#define MESALINK_BIO BIO
#define MESALINK_BUF_MEM BUF_MEM

#define BIO_new mesalink_BIO_new
#define BIO_free mesalink_BIO_free

#define BIO_read mesalink_BIO_read
#define BIO_gets mesalink_BIO_gets
#define BIO_write mesalink_BIO_write
#define BIO_puts mesalink_BIO_puts
#define BIO_flush mesalink_BIO_flush
#define BIO_ctrl mesalink_BIO_ctrl

#define BIO_s_file mesalink_BIO_s_file
#define BIO_new_file mesalink_BIO_new_file
#define BIO_new_fp mesalink_BIO_new_fp
#define BIO_set_fp mesalink_BIO_set_fp
#define BIO_get_fp mesalink_BIO_get_fp
#define BIO_read_filename mesalink_BIO_read_filename
#define BIO_write_filename mesalink_BIO_write_filename

#define BIO_s_mem mesalink_BIO_s_mem
#define BIO_new_mem_buf mesalink_BIO_new_mem_buf
#define BIO_get_mem_data mesalink_BIO_get_mem_data
#define BIO_set_mem_buf mesalink_BIO_set_mem_buf
#define BIO_get_mem_ptr mesalink_BIO_get_mem_ptr
#define BUF_MEM_new mesalink_BUF_MEM_new
#define BUF_MEM_free mesalink_BUF_MEM_free
#define BUF_MEM_grow mesalink_BUF_MEM_grow
#define BUF_MEM_grow_clean mesalink_BUF_MEM_grow_clean
#define BIO_s_socket mesalink_BIO_s_socket
#define BIO_new_socket mesalink_BIO_new_socket
#define BIO_set_fd mesalink_BIO_set_fd
#define BIO_get_fd mesalink_BIO_get_fd

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_OPENSSL_BIO_H */