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
 * which is based upon the Rustls implementation in bogo_shim.rs:
 *
 * Copyright 2016-2018 Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

extern crate env_logger;
extern crate libc;
extern crate mesalink_internals;

use std::env;
use std::process;
use std::net;
use std::io::Write;
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
        self.support_tls12 && self.version_allowed(0x0302)
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
        ErrorCode::InappropriateHandshakeMessage | ErrorCode::InappropriateMessage => {
            quit(":UNEXPECTED_MESSAGE:")
        }
        ErrorCode::AlertReceived => quit(":HANDSHAKE_FAILURE:"),
        ErrorCode::CorruptMessagePayload => quit(":GARBAGE:"),
        ErrorCode::CorruptMessage => quit(":GARBAGE:"),
        ErrorCode::DecryptError => quit(":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"),
        ErrorCode::PeerIncompatibleError => quit(":INCOMPATIBLE:"),
        ErrorCode::PeerMisbehavedError => quit(":PEER_MISBEHAVIOUR:"),
        ErrorCode::NoCertificatesPresented => quit(":NO_CERTS:"),
        ErrorCode::WebPKIError => quit(":BAD_SIGNATURE:"),
        ErrorCode::PeerSentOversizedRecord => quit(":DATA_LENGTH_TOO_LONG:"),
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
    let ctx = ssl::mesalink_CTX_new(method);
    if opts.server {
        ssl::mesalink_SSL_CTX_use_certificate_chain_file(
            ctx,
            opts.cert_file.as_ptr() as *const libc::c_char,
            0,
        );
        ssl::mesalink_SSL_CTX_use_PrivateKey_file(
            ctx,
            opts.key_file.as_ptr() as *const libc::c_char,
            0,
        );
        ssl::mesalink_SSL_CTX_check_private_key(ctx);
    }
    ctx
}

fn do_connection(opts: &Options, ctx: *mut ssl::MESALINK_CTX) {
    use std::os::unix::io::AsRawFd;
    let conn = net::TcpStream::connect(("localhost", opts.port)).expect("cannot connect");
    let mut sent_shutdown = false;
    let mut seen_eof = false;

    let ssl: *mut ssl::MESALINK_SSL = ssl::mesalink_SSL_new(ctx);

    ssl::mesalink_SSL_set_tlsext_host_name(ssl, opts.host_name.as_ptr() as *const libc::c_char);
    ssl::mesalink_SSL_set_fd(ssl, conn.as_raw_fd());

    if !opts.server {
        ssl::mesalink_SSL_connect(ssl);
    } else {
        ssl::mesalink_SSL_accept(ssl);
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
            if opts.check_close_notify {
                if !seen_eof {
                    seen_eof = true;
                } else {
                    quit_err(":CLOSE_WITHOUT_CLOSE_NOTIFY:");
                }
            } else {
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
            "-expect-client-ca-list" |
            "-expect-msg-callback" => {
                println!("not checking {} {}; NYI", arg, args.remove(0));
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
            }

            "-ocsp-response" |
            "-select-alpn" |
            "-require-any-client-certificate" |
            "-verify-peer" => {
                println!("not checking {}; disabled for MesaLink", arg);
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
            "-advertise-alpn" |
            "-use-null-client-ca-list" |
            "-enable-signed-cert-timestamps" => {
                println!("not checking {}; disabled for MesaLink", arg);
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

    for _ in 0..opts.resume_count + 1 {
        let ssl_ctx = setup_ctx(&opts);
        do_connection(&opts, ssl_ctx);
    }
}
