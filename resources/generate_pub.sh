#!/bin/bash

declare -A passwords=( ["server"]="server" ["test"]="testtest" ["test1"]="testtest1" ["server1"]="server1" ["server2"]="server2" ["server3"]="server3" ["server4"]="server4" ["server5"]="server5" ["server6"]="server6" ["server7"]="server7" ["server8"]="server8" ["server9"]="server9" ["server10"]="server10" ["server11"]="server11" ["server12"]="server12" ["server13"]="server13" ["server14"]="server14" ["server15"]="server15" ["server16"]="server16" ["server17"]="server17" ["server18"]="server18" ["server19"]="server19" ["server20"]="server20" ["server21"]="server21" ["server22"]="server22" ["server23"]="server23" ["server24"]="server24" ["server25"]="server25" ["server26"]="server26" ["server27"]="server27" ["server28"]="server28" ["server29"]="server29" ["server30"]="server30" )
keystore="key.store"
keystorepass="keystore"


for pass in "${!passwords[@]}"; do
	keytool -importkeystore -srckeystore $keystore -destkeystore $pass.p12 -deststoretype PKCS12 -srcalias $pass -srcstorepass $keystorepass -srckeypass "${passwords[$pass]}" -deststorepass "${passwords[$pass]}"
	openssl pkcs12 -in $pass.p12 -passin "pass:${passwords[$pass]}" -nodes -nocerts -out $pass.pem 
	openssl rsa -in $pass.pem -pubout -outform DER -out $pass.pub
	rm $pass.pem $pass.p12
done
