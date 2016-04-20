# PKPIN

Command line tool to extract a certificate's public key as a pin for HTTP Public Key Pinning (see https://tools.ietf.org/html/rfc7469).

## Usage

To extract a pin from a local certificate :

``./pkpin -cert certificate_path``

To extract a pin directly from a server's certificate

``./pkpin -host google.com``
