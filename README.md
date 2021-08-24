 The Transit Secrets Engine provides the ability to generate a high-entropy key to support encryption locally. The premise is to support encryption services without routing the payload to Vault. The generation of the high-entropy key relies on an existing encryption end point that supports a named key.

 To illustrate with an example, assume a named key to support encryption services of documents. The key is configured the AES-GCM with a 256-bit AES and a 96-bit nonce mode operations and is used to support encryption, decryption, key derivation, and convergent encryption.

 In general encryption-as-a-service practices, the expectation is that a service consumer routes the payload through the Transit Secrets Engine, receiving an encrypted blob in return. With the encrypted material, the service consumer is then responsible for storing the content in a desired endpoint.

 ![alt text][Vault-auth]
 ![alt text][Vault-eaas]
 ![alt text][Vault-eaas-key]
 ![alt text][Encryption-ops]

 [Vault-auth]: images/image_01_vault_auth.svg "Vault Authentication"
 [Vault-eaas]: images/image_02_transit_eaas.svg "Encryption-as-a-Service"
 [Vault-eaas-key]: images/image_03_transit_key.svg "Encryption-as-a-Service External Key"
 [Encryption-ops]: images/image_04_encryption_ops.svg "Encryption Operations"