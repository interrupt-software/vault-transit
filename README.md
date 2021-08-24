 # Background

The Transit Secrets Engine provides the ability to generate a high-entropy key to support encryption locally. The premise is to support encryption services without routing the payload to Vault. The generation of the high-entropy key relies on an existing encryption endpoint that supports a named key.

## Consumer Authentication and Authorization

Any consumer that interacts with Vault requires authentication. The basic premise is to use Vault to broker the consumer's identity against many authentication engines. Vault maintains a relationship using a role that matches a privileged role within the target identity and authentication engine. 

### Authentication
In the illustration below, the consumer uses an LDAP account to authenticate with Vault—the Vault LDAP Authentication engine aligns with the corporate LDAP Engine to verify and confirm the identity.

For example, in a code example, we can use the Python [HVAC Client](https://hvac.readthedocs.io/) library to authenticate directly with Vault.

```python
    self.client.enable_auth_backend(
        backend_type='ldap',
        description=description,
        mount_point=ldap_auth_path,
    )
```

### Authorization
Once the consumer's identity is validated, Vault links internal access policies that describe the capabilities expressed for the consumer. Polices align with Vault users and Vault groups that reflect a hierarchical structure for the consumer's environment. 

From the diagram, **Application 01** can be an individual component managed by a unique identity. Or, **Application 01** is part of a group of resources all governed by a shared identity. In either case, the linked policies describe the authorization to the secrets engine for the consumer and its identity.
 
 ![alt text][Vault-auth]

With a successful validation of the consumers's identity, Vault returns a payload that includes a bearer token. The consumer uses the token to access the desired Secrets Engine, and the policies linked to the token authorize the capabilities that the consumer can apply.

In a different scenario, interacting directly with the Vault CLI, a token can be prepared for direct access.

```bash
  vault token create -policy=app-01
```

The signifcance is the alignment with the desired policy which allows the consumer to access the resources described by the policy **app-01**.

```bash
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

The policy itself describes the encryption and decryption capabilities that apply to the Transit Secrets Engine end point.

```bash
path "transit/encrypt/app-01" {
   capabilities = [ "update" ]
}

path "transit/decrypt/app-01" {
   capabilities = [ "update" ]
}

```

## Encryption-as-a-Service

In general encryption-as-a-service practices, the expectation is that a service consumer routes the payload through the Transit Secrets Engine, receiving an encrypted blob in return. The service consumer is then responsible for storing the content in a desired endpoint with the encrypted material.

To illustrate with an example, assume a named key to support encryption services of documents. The endpoint **app-01** is configured with a AES-GCM with a 256-bit AES and a 96-bit nonce mode operations and is used to support encryption, decryption, key derivation, and convergent encryption.

In this context, the consumer routes a data blob through the encryption endpoint, and the secrets engine returns a response object that includes encrypted data. The consumer is responsible for safely storing the encrypted data on an appropriate storage medium.

![alt text][Vault-eaas]



## Generating an external data key

 ![alt text][Vault-eaas-key]

## Applying the data key for distinct encryption operations

 ![alt text][Encryption-ops]

 [Vault-auth]: images/image_01_vault_auth.svg "Vault Authentication: Access to Vault requires vetting consumer identity."
 [Vault-eaas]: images/image_02_transit_eaas.svg "Encryption-as-a-Service: Routing data through Vault Transit Secrets Engine."
 [Vault-eaas-key]: images/image_03_transit_key.svg "Encryption-as-a-Service External Key: Using a derived key from the main Transit key chain."
 [Encryption-ops]: images/image_04_encryption_ops.svg "Encryption Operations: Using the external data key for encryption and decryption."