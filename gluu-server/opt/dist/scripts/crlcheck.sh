#!/bin/bash

ICM_ROOT="/etc/certs/icm-root.pem"
GGCKEY_CERT="/etc/certs/gckey-signing.pem"
GCKEY_CRL="ldap://ldap.gss-spg.gc.ca:389/cn=CRL3995,ou=1CA-AC1,ou=GSS-SPG,o=GC,c=CA"
CBS_CERT="/etc/certs/cbs-signing.pem"
CBS_CRL="ldap://ldap.gss-spg.gc.ca:389/cn=CRL3995,ou=1CA-AC1,ou=GSS-SPG,o=GC,c=CA"

cd /tmp
umask 77

# Downnload the latest CRLs for GCKey and CBS; exit if ICM does not respond
curl $GCKEY_CRL > gckey.ldap || exit
curl $CBS_CRL > cbs.ldap || exit


# Extract the CRLs and convert to PEM
grep -Po '(?<=certificateRevocationList:: )(.+)' GCKey.ldap | \
   base64 -d | \
   openssl crl -inform DER -outform PEM -out gckey-crl.pem
grep -Po '(?<=certificateRevocationList:: )(.+)' CBS.ldap | \
   base64 -d | \
   openssl crl -inform DER -outform PEM -out cbs-crl.pem

# Verify CRL integrity; exit if failed
openssl crl crl -inform DER -CAFile $ICM_ROOT -noout -in gckey-crl.pem || exit
openssl crl crl -inform DER -CAFile $ICM_ROOT -noout -in cbs-crl.pem || exit

# Check the revocation status
if [ openssl verify -CAFile $ICM_ROOT -CRLFile gckey-crl.pem $GCKEY_CERT && 
     openssl verify -CAFile $ICM_ROOT -CRLFile cbs-crl.pem $CBS_CERT ] ; then
     echo "All Good"
else
     echo "a CSP certificate has been revoked"

