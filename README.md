 The Transit Secrets Engine provides the ability to generate a high-entropy key to support encryption locally. The premise is to support encryption services without routing the payload to Vault. The generation of the high-entropy key relies on an existing encryption end point that supports a named key.

 To illustrate with an example, assume a named key to support encryption services of documents. The key is configured the AES-GCM with a 256-bit AES and a 96-bit nonce mode operations and is used to support encryption, decryption, key derivation, and convergent encryption.

 In general encryption-as-a-service practices, the expectation is that a service consumer routes the payload through the Transit Secrets Engine, receiving an encrypted blob in return. With the encrypted material, the service consumer is then responsible for storing the content in a desired endpoint.

 ![alt text][EaaS-auth]

 [EaaS-auth]: images/Image01_Transit_EaaS.svg "Encryption-as-a-Service Authentication"