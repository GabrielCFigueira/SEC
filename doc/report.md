Crypto:

As assinaturas são feitas com SHA256 mais RSA (chave de de 2048 bits ou maior)



# Report

## Design

Java RMI was the communication logic chosen by our group. The remote object (the server), accepts the corresponding calls that the client API supports.

The project is divided in three modules: the clientAPI library, the server, and the serverAPI. The serverAPI provides the interface between the client and the server itself. Because the serverAPI is a dependency of the client, we put there other logic useful to the server and client alike, like our cryptographic functions.

Authenticity and Integrity are the main requirements in client-server communication. On the other hand, confidentiality is not a requirement (the announcements are public and there is no need to hide messages in transit) so no key distribution or ciphering logic is needed. To provide authenticity and integrity, messages are signed. Each entity has a pair of assimetric keys, in which the public one has been distributed beforehand. The keys used are 2048 bit RSA keys.

Since we are using RMI, the chosen solution to provide the above properties was this: when calling a method, the client must provide the signature of method's arguments as an extra argument. When answering back, the server must construct a type (the Response class), which has a signature as one of its fields. Exceptions can't be thrown from server to client since they are not signed.

To compute the signature, in the case of the client calling the server, the client must convert the method's arguments to a byte array (this must be in the same order that the server does to verify the signature). This byte array is "digested" using SHA-256, and then ciphered with the client's private key. The resulting byte array is sent as one of the method's arguments. The server then deciphers the signature with the public key and compares the result with the digest of the other received arguments. The same process is done when replying to the client; the server constructs the type Response and generates the signature of all its fields combined. The client then receives this Response and verifies the signature against the fields of the former.

With this logic in place, authenticity and integrity are assured. Man-in-the-middle attacks can only hope to drop/block communications, but cannot impersonate either the client or the server. However, replay attacks are still possible: to combat them, we use nonces. 

Both the server and client make use of nonces. The client sends a "client" nonce in every request he makes, and verifies if the server sent it back in the response. If the nonce is tampered with, the client can detect it through the Response's signature. The server, however, has a special remote method to request "server" nonces - except when registering (because replays attacks are trivially defeated here), the server requires a "server" nonce to be sent with the message - this nonce must be obtained beforehand. Of course, this special method for obtaining nonces can be subject to replay attacks itself, but we considered that threat harmless (no attack can be made using this threat vector, except maybe denial of service, which we were already vulnerable to).

Since all messages are signed, and the server is honest, a user can be certain that another user's announcement came from him. However, antecipating the server not being honest in a future stage of this project, and because users must be accountable for the announcements they post, we went ahead and implemented the signing of individual announcements, so a user cannot deny posting a certain announcement.


