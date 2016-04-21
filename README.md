# PKPIN

Command line tool to extract a certificate's public key as a pin for HTTP Public Key Pinning (see https://tools.ietf.org/html/rfc7469).

## Usage

To extract a pin from a local certificate :

``./pkpin -cert certificate_path``

To extract pins directly from a server's certificates chain

``./pkpin -host google.com``

To extract pin from a DER encoded public key

``./pkpin -pkey public_key_path``
