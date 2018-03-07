/*
 *   __  __                 _     _       _
 *  |  \/  | ___  ___  __ _| |   (_)_ __ | | __
 *  | |\/| |/ _ \/ __|/ _` | |   | | '_ \| |/ /
 *  | |  | |  __/\__ \ (_| | |___| | | | |   <
 *  |_|  |_|\___||___/\__,_|_____|_|_| |_|_|\_\
 *
 * Copyright (c) 2017-2018, The MesaLink Authors.
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

/* This file is a test shim for the BoringSSL-Go ('bogo') TLS test suite,
 * which is in part based upon the Rustls implementation in bogo_shim.rs.
 *
 * ISC License (ISC)
 * Copyright (c) 2016, Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 */

extern crate env_logger;
extern crate libc;
extern crate mesalink_internals;

use std::env;
use std::process;
use std::net;
use std::io::Write;
use std::ffi::CString;
use mesalink_internals::ssl::{err, ssl};
use mesalink_internals::ssl::err::ErrorCode;

static BOGO_NACK: i32 = 89;

macro_rules! println_err(
  ($($arg:tt)*) => { {
    writeln!(&mut ::std::io::stderr(), $($arg)*).unwrap();
  } }
);

#[derive(Debug)]
struct Options {
    port: u16,
    server: bool,
    resume_count: usize,
    shim_writes_first: bool,
    shim_shut_down: bool,
    check_close_notify: bool,
    host_name: String,
    use_sni: bool,
    key_file: String,
    cert_file: String,
    support_tls13: bool,
    support_tls12: bool,
    min_version: Option<u16>,
    max_version: Option<u16>,
    read_size: usize,
}

impl Options {
    fn new() -> Options {
        Options {
            port: 0,
            server: false,
            resume_count: 0,
            host_name: "example.com".to_string(),
            use_sni: false,
            shim_writes_first: false,
            shim_shut_down: false,
            check_close_notify: false,
            key_file: "".to_string(),
            cert_file: "".to_string(),
            support_tls13: true,
            support_tls12: true,
            min_version: None,
            max_version: None,
            read_size: 512,
        }
    }

    fn version_allowed(&self, vers: u16) -> bool {
        (self.min_version.is_none() || vers >= self.min_version.unwrap())
            && (self.max_version.is_none() || vers <= self.max_version.unwrap())
    }

    fn tls13_supported(&self) -> bool {
        self.support_tls13 && (self.version_allowed(0x0304) || self.version_allowed(0x7f12))
    }

    fn tls12_supported(&self) -> bool {
        self.support_tls12 && self.version_allowed(0x0303)
    }
}

fn quit(why: &str) -> ! {
    println_err!("{}", why);
    process::exit(0)
}

fn quit_err(why: &str) -> ! {
    println_err!("{}", why);
    process::exit(1)
}

fn handle_err(err: ErrorCode) -> ! {
    use std::{thread, time};

    thread::sleep(time::Duration::from_millis(100));

    match err {
        ErrorCode::TLSErrorInappropriateMessage
        | ErrorCode::TLSErrorInappropriateHandshakeMessage => quit(":UNEXPECTED_MESSAGE:"),
        ErrorCode::TLSErrorAlertReceivedRecordOverflow => quit(":TLSV1_ALERT_RECORD_OVERFLOW:"),
        ErrorCode::TLSErrorAlertReceivedHandshakeFailure => quit(":HANDSHAKE_FAILURE:"),
        ErrorCode::TLSErrorCorruptMessagePayloadAlert => quit(":BAD_ALERT:"),
        ErrorCode::TLSErrorCorruptMessagePayloadChangeCipherSpec => {
            quit(":BAD_CHANGE_CIPHER_SPEC:")
        }
        ErrorCode::TLSErrorCorruptMessagePayloadHandshake => quit(":BAD_HANDSHAKE_MSG:"),
        ErrorCode::TLSErrorCorruptMessagePayload => quit(":GARBAGE:"),
        ErrorCode::TLSErrorCorruptMessage => quit(":GARBAGE:"),
        ErrorCode::TLSErrorDecryptError => quit(":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"),
        ErrorCode::TLSErrorPeerIncompatibleError => quit(":INCOMPATIBLE:"),
        ErrorCode::TLSErrorPeerMisbehavedError => quit(":PEER_MISBEHAVIOUR:"),
        ErrorCode::TLSErrorNoCertificatesPresented => quit(":NO_CERTS:"),
        ErrorCode::TLSErrorAlertReceivedUnexpectedMessage => quit(":BAD_ALERT:"),
        ErrorCode::TLSErrorAlertReceivedDecompressionFailure => {
            quit(":SSLV3_ALERT_DECOMPRESSION_FAILURE:")
        }
        ErrorCode::TLSErrorWebpkiBadDER => quit(":CANNOT_PARSE_LEAF_CERT:"),
        ErrorCode::TLSErrorWebpkiInvalidSignatureForPublicKey => quit(":BAD_SIGNATURE:"),
        ErrorCode::TLSErrorWebpkiUnsupportedSignatureAlgorithmForPublicKey => {
            quit(":WRONG_SIGNATURE_TYPE:")
        }
        ErrorCode::TLSErrorPeerSentOversizedRecord => quit(":DATA_LENGTH_TOO_LONG:"),
        ErrorCode::TLSErrorAlertReceivedProtocolVersion => quit(":PEER_MISBEHAVIOUR:"),
        _ => {
            println_err!("unhandled error: {:?}", err);
            quit(":FIXME:")
        }
    }
}

fn setup_ctx(opts: &Options) -> *mut ssl::MESALINK_CTX {
    let method = match (opts.tls12_supported(), opts.tls13_supported(), opts.server) {
        (true, true, false) => ssl::mesalink_TLS_client_method(),
        (true, true, true) => ssl::mesalink_TLS_server_method(),
        (true, false, false) => ssl::mesalink_TLSv1_2_client_method(),
        (true, false, true) => ssl::mesalink_TLSv1_2_server_method(),
        (false, true, false) => ssl::mesalink_TLSv1_3_client_method(),
        (false, true, true) => ssl::mesalink_TLSv1_3_server_method(),
        _ => return std::ptr::null_mut(),
    };
    let ctx = ssl::mesalink_SSL_CTX_new(method as *mut ssl::MESALINK_METHOD);
    if opts.server {
        if ssl::mesalink_SSL_CTX_use_certificate_chain_file(
            ctx,
            CString::new(opts.cert_file.clone()).unwrap().as_ptr() as *const libc::c_char,
            0,
        ) != 1
        {
            println_err!("mesalink_SSL_CTX_use_certificate_chain_file failed");
            println_err!("{:?}", ErrorCode::from(err::mesalink_ERR_peek_last_error()));
        }
        if ssl::mesalink_SSL_CTX_use_PrivateKey_file(
            ctx,
            CString::new(opts.key_file.clone()).unwrap().as_ptr() as *const libc::c_char,
            0,
        ) != 1
        {
            println_err!("mesalink_SSL_CTX_use_PrivateKey_file failed");
            println_err!("{:?}", ErrorCode::from(err::mesalink_ERR_peek_last_error()));
        }
        if ssl::mesalink_SSL_CTX_check_private_key(ctx) != 1 {
            println_err!("mesalink_SSL_CTX_check_private_key failed");
            println_err!("{:?}", ErrorCode::from(err::mesalink_ERR_peek_last_error()));
        }
    }
    ssl::mesalink_SSL_CTX_set_verify(ctx, 0, None);
    ctx
}

fn do_connection(opts: &Options, ctx: *mut ssl::MESALINK_CTX) {
    use std::os::unix::io::AsRawFd;
    let conn = net::TcpStream::connect(("localhost", opts.port)).expect("cannot connect");
    let mut sent_shutdown = false;
    let mut seen_eof = false;

    let ssl: *mut ssl::MESALINK_SSL = ssl::mesalink_SSL_new(ctx);

    if ssl.is_null() {
        ssl::mesalink_SSL_free(ssl);
        quit_err("MESALINK_SSL is null");
    }

    if ssl::mesalink_SSL_set_tlsext_host_name(ssl, opts.host_name.as_ptr() as *const libc::c_char)
        != 1
    {
        ssl::mesalink_SSL_free(ssl);
        quit_err("mesalink_SSL_set_tlsext_host_name failed\n");
    }
    if ssl::mesalink_SSL_set_fd(ssl, conn.as_raw_fd()) != 1 {
        ssl::mesalink_SSL_free(ssl);
        quit_err("mesalink_SSL_set_fd failed\n");
    }

    if !opts.server {
        if ssl::mesalink_SSL_connect(ssl) != 1 {
            ssl::mesalink_SSL_free(ssl);
            quit_err("mesalink_SSL_connect failed");
        }
    } else {
        if ssl::mesalink_SSL_accept(ssl) != 1 {
            ssl::mesalink_SSL_free(ssl);
            quit_err("mesalink_SSL_accept failed");
        }
    }

    if opts.shim_writes_first {
        ssl::mesalink_SSL_write(
            ssl,
            b"hello world\0".as_ptr() as *const libc::c_uchar,
            11 as libc::c_int,
        );
    }

    let mut len;
    let mut buf = [0u8; 1024];
    loop {
        len = ssl::mesalink_SSL_read(
            ssl,
            buf.as_mut_ptr() as *mut libc::c_uchar,
            opts.read_size as libc::c_int,
        );
        if len == 0 {
            let error = ErrorCode::from(ssl::mesalink_SSL_get_error(ssl, len) as u32);
            match error {
                ErrorCode::MesalinkErrorNone => (),
                ErrorCode::MesalinkErrorWantRead | ErrorCode::MesalinkErrorWantWrite => continue,
                ErrorCode::IoErrorConnectionAborted => {
                    if opts.check_close_notify {
                        println!("close notify ok");
                    }
                    println!("EOF (tls)");
                    ssl::mesalink_SSL_free(ssl);
                    return;
                }
                ErrorCode::IoErrorConnectionReset => if opts.check_close_notify {
                    ssl::mesalink_SSL_free(ssl);
                    quit_err(":CLOSE_WITHOUT_CLOSE_NOTIFY:")
                },
                _ => handle_err(error),
            };
            if opts.check_close_notify {
                if !seen_eof {
                    seen_eof = true;
                } else {
                    ssl::mesalink_SSL_free(ssl);
                    quit_err(":CLOSE_WITHOUT_CLOSE_NOTIFY:");
                }
            } else {
                ssl::mesalink_SSL_free(ssl);
                println!("EOF (plain)");
                return;
            }
        } else if len < 0 {
            let err: ErrorCode = ErrorCode::from(err::mesalink_ERR_get_error());
            handle_err(err);
        }

        if opts.shim_shut_down && !sent_shutdown {
            ssl::mesalink_SSL_shutdown(ssl);
            sent_shutdown = true;
        }

        for b in buf.iter_mut() {
            *b ^= 0xff;
        }

        ssl::mesalink_SSL_write(ssl, buf.as_ptr() as *const libc::c_uchar, len);
    }
    // unreachable
}

fn main() {
    let mut args: Vec<_> = env::args().collect();
    env_logger::init().unwrap();

    args.remove(0);
    println!("options: {:?}", args);

    let mut opts = Options::new();

    while !args.is_empty() {
        let arg = args.remove(0);
        match arg.as_ref() {
            "-port" => {
                opts.port = args.remove(0).parse::<u16>().unwrap();
            }
            "-server" => {
                opts.server = true;
            }
            "-key-file" => {
                opts.key_file = args.remove(0);
            }
            "-cert-file" => {
                opts.cert_file = args.remove(0);
            }
            "-resume-count" => {
                opts.resume_count = args.remove(0).parse::<usize>().unwrap();
            }
           "-no-tls13" => {
                opts.support_tls13 = false;
            }
            "-no-tls12" => {
                opts.support_tls12 = false;
            }
            "-min-version" => {
                let min = args.remove(0).parse::<u16>().unwrap();
                opts.min_version = Some(min);
            }
            "-max-version" => {
                let max = args.remove(0).parse::<u16>().unwrap();
                opts.max_version = Some(max);
            }
            "-max-send-fragment" => {
                println!("not checking {}; disabled for MesaLink", arg);
                process::exit(BOGO_NACK);
            }
            "-read-size" => {
                opts.read_size = args.remove(0).parse::<usize>().unwrap();
            }
            "-tls13-variant" => {
                let variant = args.remove(0).parse::<u16>().unwrap();
                if variant != 5 {
                    println!("NYI TLS1.3 variant selection: {:?} {:?}", arg, variant);
                    process::exit(BOGO_NACK);
                }
            }
            "-max-cert-list" |
            "-expect-curve-id" |
            "-expect-resume-curve-id" |
            "-expect-peer-signature-algorithm" |
            "-expect-advertised-alpn" |
            "-expect-alpn" |
            "-expect-server-name" |
            "-expect-ocsp-response" |
            "-expect-signed-cert-timestamps" |
            "-expect-certificate-types" |
            "-expect-msg-callback" => {
                println!("not checking {} {}; NYI", arg, args.remove(0));
            }
            "-expect-client-ca-list" => {
                println!("not checking {} {}; NYI; disabled for MesaLink", arg, args.remove(0));
                process::exit(BOGO_NACK);
            }
            "-expect-secure-renegotiation" |
            "-expect-no-session-id" |
            "-expect-session-id" => {
                println!("not checking {}; NYI", arg);
            }

            "-export-keying-material" |
            "-export-label" |
            "-export-context" |
            "-use-export-context" => {
                println!("not checking {}; disabled for MesaLink", arg);
                process::exit(BOGO_NACK);
            }

            "-ocsp-response" |
            "-select-alpn" |
            "-require-any-client-certificate" |
            "-verify-peer" |
            "-signed-cert-timestamps" |
            "-advertise-alpn" |
            "-use-null-client-ca-list" |
            "-enable-signed-cert-timestamps" => {
                println!("not checking {}; disabled for MesaLink", arg);
                process::exit(BOGO_NACK);
            }
            "-shim-writes-first" => {
                opts.shim_writes_first = true;
            }
            "-shim-shuts-down" => {
                opts.shim_shut_down = true;
            }
            "-check-close-notify" => {
                opts.check_close_notify = true;
            }
            "-host-name" => {
                opts.host_name = args.remove(0);
                opts.use_sni = true;
            }

            // defaults:
            "-enable-all-curves" |
            "-renegotiate-ignore" |
            "-no-tls11" |
            "-no-tls1" |
            "-no-ssl3" |
            "-decline-alpn" |
            "-expect-no-session" |
            "-expect-session-miss" |
            "-expect-extended-master-secret" |
            "-expect-ticket-renewal" |
            "-enable-ocsp-stapling" |
            // internal openssl details:
            "-async" |
            "-implicit-handshake" |
            "-use-old-client-cert-callback" |
            "-use-early-callback" => {}

            // Not implemented things
            "-dtls" |
            "-cipher" |
            "-psk" |
            "-renegotiate-freely" |
            "-false-start" |
            "-fallback-scsv" |
            "-fail-early-callback" |
            "-fail-cert-callback" |
            "-install-ddos-callback" |
            "-advertise-npn" |
            "-verify-fail" |
            "-expect-channel-id" |
            "-send-channel-id" |
            "-select-next-proto" |
            "-p384-only" |
            "-expect-verify-result" |
            "-send-alert" |
            "-signing-prefs" |
            "-digest-prefs" |
            "-use-exporter-between-reads" |
            "-ticket-key" |
            "-tls-unique" |
            "-enable-server-custom-extension" |
            "-enable-client-custom-extension" |
            "-expect-dhe-group-size" |
            "-use-ticket-callback" |
            "-enable-grease" |
            "-enable-channel-id" |
            "-resumption-delay" |
            "-expect-early-data-info" |
            "-enable-early-data" |
            "-expect-cipher-aes" |
            "-retain-only-sha256-client-cert-initial" |
            "-use-client-ca-list" |
            "-expect-draft-downgrade" |
            "-allow-unknown-alpn-protos" |
            "-on-initial-tls13-variant" |
            "-on-initial-expect-curve-id" |
            "-enable-ed25519" |
            "-on-resume-export-early-keying-material" |
            "-export-early-keying-material" |
            "-handshake-twice" |
            "-verify-prefs" |
            "-no-op-extra-handshake" |
            "-on-resume-enable-early-data" |
            "-read-with-unfinished-write" |
            "-expect-peer-cert-file" => {
                println!("NYI option {:?}", arg);
                process::exit(BOGO_NACK);
            }

            _ => {
                println!("unhandled option {:?}", arg);
                process::exit(1);
            }
        }
    }

    println!("opts {:?}", opts);

    let ctx = setup_ctx(&opts);
    for _ in 0..opts.resume_count + 1 {
        do_connection(&opts, ctx);
    }
    ssl::mesalink_SSL_CTX_free(ctx);
}
