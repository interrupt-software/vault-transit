# Encryption with external data keys

The Transit Secrets Engine provides the ability to generate a high-entropy data key to support cryptographic operations locally. The premise is to support crypto services without routing the payload to Vault. The generation of the high-entropy key relies on an existing Transit endpoint that supports a named key.

Contents
========

* [Purpose](#purpose)
  * [Encrypting data](#encrypting-data)
  * [Decrypting data](#decrypting-data)
  * [Configure Vault](#configure-vault-for-a-basic-demonstration)
  * [Use Code Examples](#use-code-examples)
* [Encryption Patterns](#encryption-patterns)
  * [Consumer Authentication and Authorization](#consumer-authentication-and-authorization)
    * [Authentication](#authentication)
    * [Authorization](#authorization)
  * [Encryption-as-a-Service](#encryption-as-a-Service)
  * [Generating an external data key](#generating-an-external-data-key)
  * [Applying the data key](#applying-the-data-key)

---

## Purpose

The motivation for this exercise is to demonstrate practical, simplified examples of how to use an external, high-entropy data key generated with the Vault Transit Secrets Engine. There is a distinction in using Transit backends for Encrypt-as-a-Service and localized, client-side or server-side crypto operations. The instrumentation of Transit provides consumers with a unique key to fullfil operations on demmand.

The main assets to consider in this exercise are:

* **[e_aes_mode_cbc](source/e_aes_mode_cbc.py)**: Standalone encryption module that uses a Transit data key. This example applies AES.MODE_CBC encrytion and generates metadata. The `e` stands for `encription`.

* **[d_aes_mode_cbc](source/d_aes_mode_cbc.py)**: Standalone decryption module that retreives a Transit data key derived from the metadata information (created by the encryption module). The `d` stands for `decryption`.

* **[vault_client_lib](source/vault_client_lib.py)**: A simple library utility to connect to authenticate to a Vault instance. It is written in Python using the [HVAC](https://github.com/hvac/hvac) API client for Vault. This asset requires four environment variables as follows:

  * **VAULT_ADDR**: The network location of Vault. It is expressed as an URL like `http://127.0.0.1:8200`.

  * **VAULT_TOKEN**: The main authentication credential to access Vault. This is used as an authentication method to validate the identity of the consumer.

  * **VAULT_TRANSIT_KEYRING**: The label of the named key in the Transit secrets engine. In our examples we use `app-01` but this can be expressed to reflect any other conditions.

  * **VAULT_MOUNTPOINT**: The typical default for the Transit Secrets Engine is `transit`. However, it is possible to enable multiple Transit endpoints and this option allows for additional entry points.

***A note about functional vs working code***: These examples help describe working conditions but are not ready for production roles. The breakdown is functional to support different crypto operations. In real-life, these code snippets shoudl be refactored, curated, or fully rewritten by your own team.

## Encrypting data 

The essential step to encrypt new data is as follows: 

```console
  python3 e_aes_mode_cbc.py Account-Information-Form.pdf
```

The encryption module produces two files:

1. **[Account-Information-Form.pdf.aes.mode_cbc](sample_data/pdf/Account-Information-Form.pdf.aes.mode_cbc)** is the encrypted payload. 
1. **[Account-Information-Form.pdf.aes.mode_cbc.json](sample_data/pdf/Account-Information-Form.pdf.aes.mode_cbc.json)** contains the metadata associated with the encrypted payload.

## Decrypting data

To decrypt data the decryption module references an encrypted file by name. The module tries to find a corresponding JSON file with metadata. From the example above, assume that a local directory hosts an encrypted file and its corresponding metatadata:

```console
tree              
.
├── Account-Information-Form.pdf.aes.mode_cbc
└── Account-Information-Form.pdf.aes.mode_cbc.json
```

The decryption is used as follows:

```console
  python3 d_aes_mode_cbc.py Account-Information-Form.pdf.aes.mode_cbc
```

The module does the following:

1. Reads the initialization vector used for encryption and required to rebuild the encryption cipher.
1. Uses the ciphertext and connects to vault to derive the original encryption key.
1. Creates a new unencrypted file -without- the `aes.mode_cbc` extension.

```console
tree
.
├── Account-Information-Form.pdf
├── Account-Information-Form.pdf.aes.mode_cbc
└── Account-Information-Form.pdf.aes.mode_cbc.json
```

## Configure Vault for a basic demonstration

## Use Code Examples

# Encryption Patterns

## Consumer Authentication and Authorization

Any consumer that interacts with Vault requires authentication. The basic premise is to use Vault to broker the consumer's identity against many authentication engines. Vault maintains a relationship using a role that matches a privileged role within the target identity and authentication engine. 

### Authentication
In the illustration below, the consumer uses an LDAP account to authenticate with Vault—the Vault LDAP Authentication engine aligns with the corporate LDAP Engine to verify and confirm the identity.

For example, we use the Vault CLI to authenticate directly with Vault. Other methods are less involved and more automatic, and this example illustrates the implicit need to vet the consumers' identity.

```console
    vault login -method=ldap username=bender
    Password (will be hidden):
    Successfully authenticated! The policies that are associated
    with this token are listed below:
    
    default, app-01
```

### Authorization
Once the consumer's identity is validated, Vault links internal access policies that describe the capabilities expressed for the consumer. Polices align with Vault users and Vault groups that reflect a hierarchical structure for the consumer's environment. 

From the diagram, **Application 01** can be an individual component managed by a unique identity. Or, **Application 01** is part of a group of resources governed by a shared identity. In either case, the linked policies describe the authorization to the secrets engine for the consumer and its identity. 
 
![alt text][Vault-auth]

In this scenario, a policy describes the encryption and decryption capabilities as follows:

```console
# app-01.hcl 
path "transit/encrypt/app-01" {
   capabilities = [ "update" ]
}

path "transit/decrypt/app-01" {
   capabilities = [ "update" ]
}
```

Vault successfully validates the consumers' identity and returns a payload that includes a bearer token. The consumer uses the token to access the secrets engine expressed in the policy. The metadata also describes additional policies linked to the token authorize the capabilities that the consumer can apply. The significance is the alignment with the desired policy, which allows the consumer to access the resources described by the policy **app-01**.

For the authenticated user, interacting directly with the Vault CLI, a bearer token allows for direct access to the secrets engine. 

```console
  Key                  Value
  ---                  -----
  token                s.dHIi7Wf1dU2paz8GVnuc1UQO
  token_accessor       eJI7ogIBOkHaVkgVFcs2Ffeo
  token_duration       768h
  token_renewable      true
  token_policies       ["app-01" "default"]
  identity_policies    []
  policies             ["app-01" "default"]
```

## Encryption-as-a-Service

In general encryption-as-a-service practices, the expectation is that a service consumer routes the payload through the Transit Secrets Engine, receiving an encrypted blob in return. The service consumer is then responsible for storing the content in a desired endpoint with the encrypted material.

To illustrate with an example, assume a named key to support encryption services of documents. The endpoint **app-01** is configured with an AES-GCM with 256-bit AES and 96-bit nonce mode operations and is used to support encryption, decryption, key derivation, and convergent encryption.

In this context, the consumer routes a data blob through the encryption endpoint, and the secrets engine returns a response object that includes encrypted data. The consumer is responsible for safely storing the encrypted data on an appropriate storage medium.

![alt text][Vault-eaas]

Using the Vault CLI, the inline encryption operation requires passing the desired data encoded in the base64 scheme.

```console
  vault write transit/encrypt/app-01 \
  plaintext=$(base64 <<< "4024-0071-7958-8446")
```

The returning payload object includes the corresponding encrypted ciphertext. The consumer is then responsible for storing the payload for future reference.

```console
  Key            Value
  ---            -----
  ciphertext     vault:v1:DFA010gVDW5ks6S5hQIjbRjuIhEXSnLm9gjYhRPqd+rZEdShzkXG0zb9kadL35g=
  key_version    1
```

For completeness, it is relevant to explain that the decryption procedure follows a similar pattern. With the successful authentication of the consumer, the policy allows for decryption services. The consumer then routes the ciphertext through Vault to obtain unencrypted data.

```console
  vault write transit/decrypt/app-01 \ 
  ciphertext="vault:v1:DFA010gVDW5ks6S5hQIjbRjuIhEXSnLm9gjYhRPqd+rZEdShzkXG0zb9kadL35g="

  Key          Value
  ---          -----
  plaintext    NDAyNC0wMDcxLTc5NTgtODQ0Ng==
```

The data produced is encoded in the base64 scheme and requires decoding.

```console
   base64 --decode <<< "NDAyNC0wMDcxLTc5NTgtODQ0Ng=="
   4024-0071-7958-8446
```

In the end, the consumer can extract the original data payload and present it to the next operation.

## Generating an external data key

There are situations in which routing data through the Transit Secrets Engine is not ideal. There can be multiple reasons, but the most common are:

* The payload is too large to transfer over the network when data blobs are about two Gigabytes in size or more.
* The operation must be completed locally on a document or abstract object, not on a single string of data.

The first step is to update the appropriate capabilities to the consumer's policy. This ensures that the consumer can generate a new high-entropy key and value using **app-01** as the encryption key.

```console
# app-01.hcl 
path "transit/encrypt/app-01" {
   capabilities = [ "update" ]
}

path "transit/decrypt/app-01" {
   capabilities = [ "update" ]
}

path "transit/datakey/plaintext/app-01" {
   capabilities = [ "update" ]
}
```

In a routine operation, the consumer can generate a request which responds with `ciphertext` and `plaintext` values.

```console
  vault write -f transit/datakey/plaintext/app-01 
  Key            Value
  ---            -----
  ciphertext     vault:v1:q98ntBqvUL+x1/8IF2hb4/V2nw/OAezbS7K+q5PPYg6d+SF4HAm1cbJwDlt/YUg4GD9jv6SD60imhf9/
  key_version    1
  plaintext      18rTYrIjBGejLvptBTpcbnE7k1U29lOFys1OwW2S1yQ=
```

 ![alt text][Vault-eaas-key]

 The ciphertext returned reflects the encrypted value of the plaintext. The ciphertext is used to recall the data key when needed. The consumer must preserve the ciphertext and the relationship to the data file or data object involved in the encryption or decryption operations.

 The plaintext is a bytes object of a named data key. The bytes object can be 128, 256 or 256 bits in length, and it is encoded in the base64 scheme. Once unwrapped, the consumer uses this object to create a block `cipher`. The cipher must be combined with a mode of operation to support symmetric or asymmetric encryption MODES.
 
## Applying the data key for distinct encryption operations

In the example for encryption operations, we reference Advanced Encryption Standard (AES) MODE Cipher-Block Chaining (CBC). Depending on the implementation library used for this operation, there can be additional parameters to fulfill. For instance, with Python tests, the AES.MODE_CBC requires an initialization vector (iv) parameter that is unique to the operation. Hence, it also needs to be documented in the metadata for future reference.

 There are multiple techniques to accomplish the work. For illustration purposes, we save the metadata externally in a JSON object for future reference. In other situations, the data is added to the encrypted payload, and positional information is written in the header of the encrypted object itself.

 ![alt text][Encryption-ops]

 Lastly, for every encryption function, there must be a decryption function. And, in every situation, a newly created cipher must use a key to perform the assigned task. For encryption operations, the key is generated directly from the Transit Secrets Engine. Once the procedure completes, the key is discarded, and the corresponding ciphertext is saved. The ciphertext also needs to have a relational link to the object used in the encryption process.

 When the consumer decrypts an encrypted object, it uses the ciphertext to unencrypt the original data using the **app-01** encryption key. With the original data key reproduced, a cipher is used to decrypt the encrypted object.

 [Vault-auth]: images/image_01_vault_auth.svg "Vault Authentication: Access to Vault requires vetting the consumer's identity"
 [Vault-eaas]: images/image_02_transit_eaas.svg "Encryption-as-a-Service: Routing data through Vault Transit Secrets Engine"
 [Vault-eaas-key]: images/image_03_transit_key.svg "Encryption-as-a-Service External Key: Using a high-entropy key from the main Transit key chain"
 [Encryption-ops]: images/image_04_encryption_ops.svg "Encryption Operations: Using the external data key for encryption and decryption operations"