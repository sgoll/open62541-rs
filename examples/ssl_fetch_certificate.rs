use anyhow::Context as _;
use itertools::Itertools as _;
use open62541::{
    der::{pem::LineEnding, EncodePem as _},
    Certificate, ClientBuilder,
};

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let endpoint_descriptions = ClientBuilder::default()
        .get_endpoints("opc.tcp://localhost")
        .context("get endpoints")?;

    let server_certificates = endpoint_descriptions
        .iter()
        .filter_map(|endpoint_description| {
            endpoint_description
                .server_certificate()
                .as_bytes()
                .map(|bytes| Certificate::from_bytes(bytes).x509())
        })
        .collect::<Result<Vec<_>, _>>()
        .context("parse certificates")?;

    // Include consecutive (!) identical certificates only once.
    let unique_certificates = server_certificates
        .into_iter()
        .dedup_by(|a, b| a.tbs_certificate().serial_number() == b.tbs_certificate().serial_number())
        .collect::<Vec<_>>();

    println!("Found {} server certificate(s)", unique_certificates.len());

    for (index, certificate) in unique_certificates.iter().enumerate() {
        println!();
        println!("# Certificate {}", index + 1);
        println!(
            "Subject common name: {}",
            certificate.tbs_certificate().subject()
        );
        println!(
            "Validity not before: {}",
            certificate.tbs_certificate().validity().not_before
        );
        println!(
            "Validity not after: {}",
            certificate.tbs_certificate().validity().not_after
        );
        println!(
            "Serial number: {}",
            certificate.tbs_certificate().serial_number()
        );
        println!();
        println!(
            "{}",
            certificate
                .to_pem(LineEnding::LF)
                .context("get certificate PEM")?
        );
    }

    Ok(())
}
