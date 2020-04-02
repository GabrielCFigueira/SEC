# Java KeyStore

Create keystore and generate RSA keypair

$ keytool -genkeypair -alias keyname -keystore key.store -keyalg RSA -storetype jks


## Current keystore keys 

Keystore password: keystore

Private keys:

	server password: server

	test password: testtest

	test1 password: testtest1

## Exporting public keys

DO these steps for every key

First we need to convert the jks to pkcs12

$ keytool -importkeystore -srckeystore key.store -deststoretype PKCS12 -destkeystore keyname.p12 -srcalias keyname

$ openssl pkcs12 -in keyname.p12 -nodes -nocerts -out keyname.pem

$ openssl rsa -in keyname.pem -pubout -outform DER -out keyname.pub

$ rm keyname.p12 keyname.pem
