/* err.h
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

#ifndef MESALINK_ERR_H
#define MESALINK_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

enum ErrorCode
{
    INAPPROPRIATE_MESSAGE = -401,
    INAPPROPRIATE_HANDSHAKE_MESSAGE = -402,
    CORRUPT_MESSAGE = -403,
    CORRUPT_MESSAGE_PAYLOAD = -404,
    NO_CERTIFICATES_PRESENTED = -405,
    DECEYPT_ERROR = -406,
    PEER_INCOMPATIBLE_ERROR = -407,
    PEER_MISBEHAVED_ERROR = -408,
    ALERT_RECEIVED = -409,
    WEBPKI_ERROR = -410,
    INVALID_SCT = -411,
    GENERAL = -412,
    FAILED_TO_GET_CURRENT_TIME = -413,
};

MESALINK_API char *mesalink_ERR_error_string(unsigned long e, char *buf);
MESALINK_API void mesalink_ERR_error_string_n(unsigned long e, char *buf, size_t len);
MESALINK_API const char *ERR_reason_error_string(unsigned long e);

MESALINK_API unsigned long mesalink_ERR_get_error(void);
MESALINK_API unsigned long mesalink_ERR_peek_last_error(void);
MESALINK_API void mesalink_ERR_clear_error(void);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MESALINK_ERR_H */
