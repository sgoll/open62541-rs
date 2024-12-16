use anyhow::Context as _;
use open62541::{
    der::{pem::LineEnding, EncodePem as _},
    ua,
};

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let subject = ua::Array::from_slice(&[
        ua::String::new("C=DE").context("create string")?,
        ua::String::new("O=SampleOrganization").context("create string")?,
        ua::String::new("CN=Open62541Server@localhost").context("create string")?,
    ]);

    let subject_alt_name = ua::Array::from_slice(&[
        ua::String::new("DNS:localhost").context("create string")?,
        ua::String::new("URI:urn:open62541.server.application").context("create string")?,
    ]);

    let params = ua::KeyValueMap::from_slice(&[
        (
            // We use a reduced key size to make this example run faster. Use a larger key size for
            // production purposes.
            &ua::QualifiedName::ns0("key-size-bits"),
            &ua::Variant::scalar(ua::UInt16::new(1024)),
        ),
        (
            &ua::QualifiedName::ns0("expires-in-days"),
            &ua::Variant::scalar(ua::UInt16::new(30)),
        ),
    ]);

    let (certificate, private_key) = open62541::create_certificate(
        &subject,
        &subject_alt_name,
        &ua::CertificateFormat::PEM,
        Some(&params),
    )
    .context("create certificate")?;

    let certificate = certificate.x509().context("parse certificate")?;

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

    let private_key = private_key.pkcs1().context("parse private key")?;

    println!(
        "{}",
        private_key
            .to_pem(LineEnding::LF)
            .context("get private key PEM")?
    );

    Ok(())
}
