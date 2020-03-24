#!/bin/bash

declare -A passwords=( ["server"]="server" ["test"]="testtest" ["test1"]="testtest1" )
keystore="key.store"
keystorepass="keystore"


for pass in "${!passwords[@]}"; do
	keytool -importkeystore -srckeystore $keystore -destkeystore $pass.p12 -deststoretype PKCS12 -srcalias $pass -srcstorepass $keystorepass -srckeypass "${passwords[$pass]}" -deststorepass "${passwords[$pass]}"
	openssl pkcs12 -in $pass.p12 -passin "pass:${passwords[$pass]}" -nodes -nocerts -out $pass.pem 
	openssl rsa -in $pass.pem -pubout -outform DER -out $pass.pub
	rm $pass.pem $pass.p12
done
