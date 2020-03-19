# SECproj
SEC project

RMI Instructions

1)On the Server directory: mvn -U clean install exec:java -Dexec.mainClass="sec.dpas.Server"
2)On the Client directory: mvn -U clean install exec:java -Dexec.mainClass="sec.dpas.Client"

generate rsa keypairs:
$ openssl genrsa -out priv.pem 4096
$ openssl pkcs8 -topk8 -inform PEM -outform DER -in priv.pem -out priv.key -nocrypt
$ openssl rsa -in priv.pem -pubout -outform DER -out pub.key
