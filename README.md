# SECproj
SEC project

## Requirements

Java version: 8 or higher
Maven version: 3.6.3

## Compile and run the tests

1) mvn clean install in project folder

2) mvn clean test in project folder

## Run the interface:

1)On the Server directory: mvn exec:java -Dexec.mainClass="sec.dpas.Server"

2)On the Client directory: mvn exec:java -Dexec.mainClass="sec.dpas.Client"

## After running the interface

Remove the .txt files to avoid conflicts with the automatic tests: rm resources/*.txt

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
