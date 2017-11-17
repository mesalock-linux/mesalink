/* openssl/err.h
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

#include <mesalink/ssl.h>
#include <mesalink/err.h>

#define ERR_load_crypto_strings         mesalink_ERR_load_error_strings
#define ERR_free_strings                mesalink_ERR_free_error_strings

#define ERR_error_string                mesalink_ERR_error_string
#define ERR_error_string_n              mesalink_ERR_error_string_n
#define ERR_reason_error_string         mesalink_ERR_reason_error_string

#define ERR_get_error                   mesalink_ERR_get_error
#define ERR_peek_last_error             mesalink_ERR_peek_last_error
#define ERR_clear_error                 mesalink_ERR_clear_error
