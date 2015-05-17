#!/usr/bin/env bash
#
# Run the NIST X.509 Path Validation tests
#
#   These are documented in http://csrc.nist.gov/groups/ST/crypto_apps_infra/documents/PKI%20Testing%20Page.htm
#
#

failed=0
success=0
openssl=`which openssl`

echo -n "[*] Running tests..."

for i in {1..18}; do
    cert_path="test_vectors/X509tests/test$i/cert_path.crt"

    # Convert the individual certificates into base64, and concatenate into single file
    if [ ! -f "$cert_path" ]; then
        if [ ! -f "$openssl" ]; then 
            echo -e "\nneed openssl"
            exit -1
        fi
        end_cert=`echo test_vectors/X509tests/test$i/End\ Certificate*.crt`
        intermediate_certs=`ls test_vectors/X509tests/test$i/Intermediate\ Certificate*.crt 2>/dev/null | sort -r | tr ' ' 'Z'`
        trust_anchor=`echo test_vectors/X509tests/test$i/Trust\ Anchor\ CP*.crt`
        if [ ! -f "$trust_anchor" ]; then
            echo "no such file $trust_anchor"
            exit -1
        fi 
        if [ ! -f "$end_cert" ]; then
            echo "no such file $end_cert"
            exit -1
        fi
        "$openssl" x509 -inform DER -in "$end_cert" > "$cert_path"
        for intermediate_cert in $intermediate_certs; do
            intermediate_cert=`echo "$intermediate_cert" | tr 'Z' ' '`
            if [ ! -f "$intermediate_cert" ]; then
                echo "no such file $intermediate_cert"
                exit -1
            fi
            "$openssl" x509 -inform DER -in "$intermediate_cert" >> "$cert_path"
        done
        "$openssl" x509 -inform DER -in "$trust_anchor" >> "$cert_path"
    fi

    ../tools/mintls_cert verify "$cert_path" > /tmp/tmp.out
    if [ ! -f X509test_results/test$i.out ]; then
        echo "Validation stub" > X509test_results/test$i.out
        [ 1  = 2 ]
    else
        diff -q /tmp/tmp.out X509test_results/test$i.out >/dev/null
    fi
    if [ $? -ne 0 ]; then
       echo -n "[E] Validation test $i failed: "
       diff /tmp/tmp.out X509test_results/test$i.out
       mv /tmp/tmp.out X509test_results/test$i.result
       failed=$((failed+1))
    else
       #echo "passed."
       success=$((success+1))
    fi
done

if [ $failed -ne 0 ]; then
echo -e "\n[E] $failed/$((success+failed)) path validations failed"
else
echo " $success/$((success)) path validations passed"
fi

exit $failed
