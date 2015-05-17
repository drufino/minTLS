#!/bin/bash

failed=0
success=0

for cert in test_certs/*.crt; do
    #echo -n "[*] $cert...."
    ../tools/mintls_cert "$cert" | diff test_certs/`basename $cert .crt`.txt - 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
       echo "$cert failed."
       failed=$((failed+1))
    else
       #echo "passed."
       success=$((success+1))
    fi
done

echo "    $failed out of $((success+failed)) certificate regressions."

exit $failed
