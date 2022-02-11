# crt-sh

A simple rust wrapper around [crt.sh](https://crt.sh).

## Usage

Get the certificate overview for a domain:

```rs
let certs: Vec<CrtShEntry> = get_entries("example.com").await.unwrap();
```

Get a specific certificate (identified by the previous returned crt.sh ID)
```rs 
let cert: pem::Pem = get_certificate(5813209289).await.unwrap();
```
