use chrono::NaiveDate;
use scraper::{Html, Selector};
use table_extract::Table;

type Result<T> = std::result::Result<T, CrtShError>;

#[derive(Debug, PartialEq, Eq)]
pub struct CrtShEntry {
    pub id: usize,
    pub logged_at: NaiveDate,
    pub not_before: NaiveDate,
    pub not_after: NaiveDate,
    pub common_name: String,
    pub matching_identities: Vec<String>,
    pub issuer: String,
}

#[derive(Debug)]
pub enum CrtShError {
    Request(reqwest::Error),
    TableNotFound,
    InvalidEntry(&'static str, Vec<String>),
    CertificateError(pem::PemError),
}

impl From<reqwest::Error> for CrtShError {
    fn from(e: reqwest::Error) -> Self {
        CrtShError::Request(e)
    }
}

pub async fn get_certificate(id: usize) -> Result<pem::Pem> {
    let cert = reqwest::get(&format!("https://crt.sh/?d={}", id))
        .await?
        .bytes()
        .await?;
        
    Ok(pem::parse(cert).map_err(|e| CrtShError::CertificateError(e))?)
}

pub async fn get_entries<T: AsRef<str>>(domain: T) -> Result<Vec<CrtShEntry>> {
    let html = reqwest::get(format!("https://crt.sh/?q={}", domain.as_ref()))
        .await?
        .text()
        .await?;

    println!("{}", html);

    let table = Table::find_by_headers(&html, &["Common Name"]).ok_or(CrtShError::TableNotFound)?;
    let mut certificates = Vec::new();
    let not_after_header = format!(
        "<a href=\"?q={}&amp;dir=v&amp;sort=4&amp;group=none\">Not After</a>",
        domain.as_ref()
    );
    let id_header = format!(
        "<a href=\"?q={}&amp;dir=v&amp;sort=0&amp;group=none\">crt.sh ID</a>",
        domain.as_ref()
    );
    let issuer_header = format!(
        "<a href=\"?q={}&amp;dir=v&amp;sort=3&amp;group=none\">Issuer Name</a>",
        domain.as_ref()
    );
    let logged_at_header = format!(
        "&nbsp;<a href=\"?q={}&amp;dir=v&amp;sort=1&amp;group=none\">Logged At</a>&nbsp;\n ⇧",
        domain.as_ref()
    );
    let not_before_header = format!(
        "<a href=\"?q={}&amp;dir=v&amp;sort=2&amp;group=none\">Not Before</a>",
        domain.as_ref()
    );

    let link_selector = Selector::parse("a").unwrap();

    for row in &table {
        if row.as_slice().is_empty() {
            continue;
        }
        let not_after_str = row.get(&not_after_header).ok_or(CrtShError::InvalidEntry(
            "Not After not found",
            row.as_slice().to_vec(),
        ))?;
        let not_before_str = row.get(&not_before_header).ok_or(CrtShError::InvalidEntry(
            "Not Before not found",
            row.as_slice().to_vec(),
        ))?;
        let logged_at_str = row.get(&logged_at_header).ok_or(CrtShError::InvalidEntry(
            "Logged At not foun",
            row.as_slice().to_vec(),
        ))?;
        let id_str = row.get(&id_header).ok_or(CrtShError::InvalidEntry(
            "Crt.sh Id not found",
            row.as_slice().to_vec(),
        ))?;
        let issuer_str = row.get(&issuer_header).ok_or(CrtShError::InvalidEntry(
            "Issuer not found",
            row.as_slice().to_vec(),
        ))?;
        let common_name = row.get("Common Name").ok_or(CrtShError::InvalidEntry(
            "Common Name not found",
            row.as_slice().to_vec(),
        ))?;
        let matching_identities =
            row.get("Matching Identities")
                .ok_or(CrtShError::InvalidEntry(
                    "Matching identities not found",
                    row.as_slice().to_vec(),
                ))?;

        let id_without_tags = Html::parse_fragment(id_str)
            .select(&link_selector)
            .next()
            .ok_or(CrtShError::InvalidEntry(
                "Crt.sh Id not found",
                row.as_slice().to_vec(),
            ))?
            .inner_html()
            .trim()
            .to_string();

        let issuer_without_tags = Html::parse_fragment(issuer_str)
            .select(&link_selector)
            .next()
            .ok_or(CrtShError::InvalidEntry(
                "Issuer not found",
                row.as_slice().to_vec(),
            ))?
            .inner_html()
            .trim()
            .to_string();

        let cert = CrtShEntry {
            common_name: common_name.to_string(),
            not_after: NaiveDate::parse_from_str(not_after_str, "%Y-%m-%d").map_err(|_| {
                CrtShError::InvalidEntry("Not After not in valid format", row.as_slice().to_vec())
            })?,
            logged_at: NaiveDate::parse_from_str(logged_at_str, "%Y-%m-%d").map_err(|_| {
                CrtShError::InvalidEntry("Logged At not in valid format", row.as_slice().to_vec())
            })?,
            not_before: NaiveDate::parse_from_str(not_before_str, "%Y-%m-%d").map_err(|_| {
                CrtShError::InvalidEntry("Not Before not in valid format", row.as_slice().to_vec())
            })?,
            id: id_without_tags.parse::<usize>().map_err(|_| {
                CrtShError::InvalidEntry("Crt.sh Id not u64", row.as_slice().to_vec())
            })?,
            issuer: issuer_without_tags,
            matching_identities: matching_identities
                .split("<br>")
                .map(|s| s.trim().to_string())
                .collect(),
        };
        certificates.push(cert);
    }

    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;
    use tokio::runtime::Runtime;

    use crate::{get_certificate, get_entries, CrtShEntry};

    const TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIHNjCCBh6gAwIBAgIQAlIW4cSZjiYyql0dqYW0PDANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSkwJwYDVQQDEyBE
aWdpQ2VydCBUTFMgUlNBIFNIQTI1NiAyMDIwIENBMTAeFw0yMTEyMTAwMDAwMDBa
Fw0yMjEyMDkyMzU5NTlaMIGBMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZv
cm5pYTEUMBIGA1UEBxMLTG9zIEFuZ2VsZXMxLTArBgNVBAoTJFZlcml6b24gRGln
aXRhbCBNZWRpYSBTZXJ2aWNlcywgSW5jLjEYMBYGA1UEAxMPd3d3LmV4YW1wbGUu
b3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoDBCVtcLoRG58wvs
zPJMsG8TAmvPB/OF8EKPxVSYgW56kzi2+kZCs1zmyTtZk2EkQyD1eonJd63/h8gI
24b13GF1ll/c8AjKOrleD/o3fGVqyggnHp3YCj+eENtFJZoDcrr1J9mw6zbUkzmM
EWxfMxRY5cCIxR96IRTM0qdfHHMf2QMgbnoI7xdO474owE/gcWMhBHePj0sr6Aui
vpd+UG+4Ozdjf6QMmf+WosN/ynwhuv2Q0T8FpDRw1oSOpQDcKXz9lstDrjmPLcat
2MIdm+RfnFGci/5tSWJbx80eGJbOxioHt3GAYHKsVxIAkEMPI76pcHHW5XuFo00F
iCHHIwIDAQABo4ID2TCCA9UwHwYDVR0jBBgwFoAUt2ui6qiqhIx56rTaD5iyxZV2
ufQwHQYDVR0OBBYEFG3g+qTIbys3Dg1NyBKa0QeBaGBEMIGBBgNVHREEejB4gg93
d3cuZXhhbXBsZS5vcmeCC2V4YW1wbGUubmV0ggtleGFtcGxlLmVkdYILZXhhbXBs
ZS5jb22CC2V4YW1wbGUub3Jngg93d3cuZXhhbXBsZS5jb22CD3d3dy5leGFtcGxl
LmVkdYIPd3d3LmV4YW1wbGUubmV0MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAU
BggrBgEFBQcDAQYIKwYBBQUHAwIwgY8GA1UdHwSBhzCBhDBAoD6gPIY6aHR0cDov
L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VExTUlNBU0hBMjU2MjAyMENBMS00
LmNybDBAoD6gPIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VExT
UlNBU0hBMjU2MjAyMENBMS00LmNybDA+BgNVHSAENzA1MDMGBmeBDAECAjApMCcG
CCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwfwYIKwYBBQUH
AQEEczBxMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wSQYI
KwYBBQUHMAKGPWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRM
U1JTQVNIQTI1NjIwMjBDQTEtMS5jcnQwDAYDVR0TAQH/BAIwADCCAX0GCisGAQQB
1nkCBAIEggFtBIIBaQFnAHYARqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy/HD+
bUcAAAF9osbrcAAABAMARzBFAiEA5RwolQhRMWvTnyCNwRK/v/mG2S9Df0gRhXWK
pJuhG+YCIENHIK5yyKs3fLL9nlO9ckl5b9xbo8K3FP+N+keoBB+ZAHUAQcjKsd8i
RkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvYAAAF9osbrPAAABAMARjBEAiB7M05v
Xh19tt1EbNsZEqb7/PrJRfeMOLz1O1UTOKCH1gIgf4nU/wBGtMERQuxeebdmf3wz
+5Q0pOgf2rEi4a016SUAdgDfpV6raIJPH2yt7rhfTj5a6s2iEqRqXo47EsAgRFwq
cwAAAX2ixut2AAAEAwBHMEUCIQDQjMsK3kzqSnGNY9Y5k0bLwo2/YN/2F0oaqXXi
NdOjJAIgFw06n1b8M6QdD98zAsRR4e52c0O7YzvrJXfRSE3JnfowDQYJKoZIhvcN
AQELBQADggEBAKVUNGn++wNr8agdWjZ5WY9cYqJjmQTQY3g5VkQMNaJiXIivehDU
TcFPqtfimTlVlVrfLGxYRAOZrzkGoQjUf99IKJW4ZUOQ0WDsKoaowU1qfzpGTwbr
jzmed2HbLlTP8NjQpYPMEIIiRQUC1iUK+0lf0UOq5mLJ3Cq3yL9UbOyhYTX9ha05
c5/nZHvhwCNvyie5RT6jWLcMH69hPS2DGiVr8HG4iV1W1F3/X+HeBOsEo1YyYlII
SCHB72Cijki2QiAHzPqy71H9MDt9jH2jbYKVRIDRJ20eF2Y1+rk7qQjwLoBM44Af
W9N7n6eEuv2HEWnaVBymoUjHaSEzYydzVOg=
-----END CERTIFICATE-----
"#;

    #[test]
    fn basic() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let old_cert = CrtShEntry {
                common_name: "www.example.com".to_string(),
                id: 24560621,
                logged_at: NaiveDate::from_ymd(2016, 7, 14),
                not_after: NaiveDate::from_ymd(2017, 7, 14),
                not_before: NaiveDate::from_ymd(2016, 7, 14),
                issuer: "C=US, O=\"thawte, Inc.\", CN=thawte SSL CA - G2".to_string(),
                matching_identities: vec![
                    "*.example.com".to_string(),
                    "example.com".to_string(),
                    "m.example.com".to_string(),
                    "www.example.com".to_string(),
                ],
            };
            let certs = get_entries("example.com").await;

            assert!(certs.is_ok());

            let certs = certs.unwrap();

            assert!(certs.contains(&old_cert));
        });
    }

    #[test]
    fn certificate() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let test_cert = pem::parse(TEST_CERT).unwrap();

            let remote_cert = get_certificate(5813209289).await;
            assert!(remote_cert.is_ok());

            let remote_cert = remote_cert.unwrap();

            assert_eq!(remote_cert, test_cert);
        });
    }
}
