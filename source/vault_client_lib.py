import logging
import hvac
import os


class vault_client:
    def __init__(self):
        self.client = None

    def connect(self, vault_addr=None, vault_token=None):
        """
        Sets the hvac client to communicate with Vault

        :param str vault_addr: the Vault server url
        :param str vault_token: the Vault token
        """
        if not vault_addr or not vault_token:
            logging.warning(
                "Vault server url or token missing. Looking for environment variables `VAULT_ADDR` and `VAULT_TOKEN`.")

            if 'VAULT_ADDR' in os.environ and 'VAULT_TOKEN' in os.environ:
                vault_addr = os.environ.get('VAULT_ADDR')
                vault_token = os.environ.get('VAULT_TOKEN')
            else:
                logging.error(
                    "`VAULT_ADDR` and `VAULT_TOKEN` must be set in your environment.")
                exit()

        self.client = hvac.Client(
            url=vault_addr,
            token=vault_token,
            verify=True,
        )

        if not self.client.is_authenticated():
            print("Vault authentication failure.")
            self.client = None

        return self

    def get_datakey(self, vault_key_name=None):
        """
        Returns the payload for a new high-entropy key and the value encrypted with the named key. The data key is included in base64 encoded plaintext, and the ciphertext is used as reference to re-obtain the derived key payload.

        :param str vault_key_name: Name of the encryption key to use to encrypt the datakey
        """
        if not vault_key_name:
            logging.warning(
                "Vault Transit key name missing. Looking for environment variable `VAULT_TRANSIT_KEYNAME`.")

            if 'VAULT_TRANSIT_KEYNAME' in os.environ:
                vault_key_name = os.environ.get('VAULT_TRANSIT_KEYNAME')
            else:
                logging.error(
                    "`VAULT_TRANSIT_KEYNAME` must be set in your environment.")
                exit()

        response = None

        try:
            response = self.client.secrets.transit.generate_data_key(
                name=vault_key_name,
                key_type='plaintext',
            )
        except:
            logging.error("Unable to authenticate with Vault.")
            exit()

        return response

    def decrypt_datakey(self, ciphertext=None, vault_key_name=None):
        """
        Returns the payload for a new high-entropy key in plaintext.

        :param str ciphertext: Specifies the ciphertext to decrypt. This should be a part of the derived key payload.
        :param str vault_key_name: Name of the encryption key to use to initially encrypt the datakey
        """
        if not vault_key_name:
            logging.warning(
                "Vault Transit key name missing. Looking for environment variable `VAULT_TRANSIT_KEYNAME`.")

            if 'VAULT_TRANSIT_KEYNAME' in os.environ:
                vault_key_name = os.environ.get('VAULT_TRANSIT_KEYNAME')
            else:
                logging.error(
                    "`VAULT_TRANSIT_KEYNAME` must be set in your environment.")
                exit()

        response = None

        try:
            response = self.client.secrets.transit.decrypt_data(
                name=vault_key_name,
                ciphertext=ciphertext
            )
        except:
            logging.error("Unable to retreive DEK.")
            exit()

        return response


if __name__ == "__main__":

    client = vault_client()
    client.connect()
    response = client.get_datakey()
    print(response)

    plaintext = response['data']['plaintext']
    ciphertext = response['data']['ciphertext']

    print(client.decrypt_datakey(ciphertext))
