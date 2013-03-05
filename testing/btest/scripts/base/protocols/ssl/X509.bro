# Test output of the X509 data-structure

# @TEST-EXEC: bro -r $TRACES/tls-conn-with-extensions.trace %INPUT > output
# @TEST-EXEC: btest-diff output

event x509_certificate(c: connection, is_orig: bool, cert: X509, chain_idx: count, chain_len: count, der_cert: string) {
	print cert;
}

