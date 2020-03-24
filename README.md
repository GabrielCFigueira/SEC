# SECproj
SEC project

RMI Instructions

1)On the Server directory: mvn -U clean install exec:java -Dexec.mainClass="sec.dpas.Server"
2)On the Client directory: mvn -U clean install exec:java -Dexec.mainClass="sec.dpas.Client"


#OpenSSL

generate rsa keypairs:

$ openssl genrsa -out priv.pem 4096

$ openssl pkcs8 -topk8 -inform PEM -outform DER -in priv.pem -out priv.key -nocrypt

$ openssl rsa -in priv.pem -pubout -outform DER -out pub.key


#Java KeyStore

Create keystore and generate RSA keypair

$ keytool -genkeypair -alias keyname -keystore key.store -keyalg RSA -storetype jks


## Keystore passwords

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
