// Print the Subject of all extracted trust anchors.

use rustls_native_certs;
use std::io::{BufRead, Error};
use x509_parser::prelude::*;

struct Printer {}

impl rustls_native_certs::RootStoreBuilder for Printer {
    fn load_der(&mut self, der: Vec<u8>) -> Result<(), Error> {
        let (_, cert) = parse_x509_certificate(&der).unwrap();
        println!("{}", cert.tbs_certificate.subject);
        Ok(())
    }
    fn load_pem_file(&mut self, rd: &mut dyn BufRead) -> Result<(), Error> {
        let mut buf = vec![];
        rd.read_to_end(&mut buf)?;
        for pem in Pem::iter_from_buffer(&mut buf) {
            let pem = pem.expect("Reading next PEM block failed");
            let cert = pem.parse_x509().expect("X.509: decoding DER failed");
            println!("{}", cert.tbs_certificate.subject);
        }
        Ok(())
    }
}

fn main() {
    rustls_native_certs::build_native_certs(&mut Printer {}).unwrap();
}
