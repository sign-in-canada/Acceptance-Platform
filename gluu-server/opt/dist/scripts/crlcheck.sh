#!/bin/bash

ICM_ROOT="/opt/dist/certs/icm-root.pem"
GCKEY_CERT="/opt/dist/certs/gckey-signing.pem"
GCKEY_CRL="ldap://ldap.gss-spg.gc.ca:389/cn=CRL3995,ou=1CA-AC1,ou=GSS-SPG,o=GC,c=CA"
CBS_CERT="/opt/dist/certs/cbs-signing.pem"
CBS_CRL="ldap://ldap.gss-spg.gc.ca:389/cn=CRL4740,ou=1CA-AC1,ou=GSS-SPG,o=GC,c=CA"

cd /tmp
umask 77

# Downnload the latest CRLs for GCKey and CBS; exit if ICM does not respond
curl -s $GCKEY_CRL > GCKey.ldap || exit
curl -s $CBS_CRL > CBS.ldap || exit

# Extract the CRLs and convert to PEM
grep -Po '(?<=certificateRevocationList;binary:: )(.+)' GCKey.ldap | \
   base64 -d | \
   openssl crl -inform DER -outform PEM -out gckey-crl.pem
grep -Po '(?<=certificateRevocationList;binary:: )(.+)' CBS.ldap | \
   base64 -d | \
   openssl crl -inform DER -outform PEM -out cbs-crl.pem

# Verify CRL integrity; exit if failed
openssl crl -inform PEM -CAfile $ICM_ROOT -noout -in gckey-crl.pem || exit
openssl crl -inform PEM -CAfile $ICM_ROOT -noout -in cbs-crl.pem || exit

# Check the revocation status; shutdown passport if either is revoked
openssl verify -CAfile $ICM_ROOT -crl_check -CRLfile gckey-crl.pem $GCKEY_CERT || systemctl stop passport
openssl verify -CAfile $ICM_ROOT -crl_check -CRLfile cbs-crl.pem $CBS_CERT  || systemctl stop passport
