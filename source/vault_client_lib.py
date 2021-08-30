import logging
import hvac
import os
import pprint
import sys


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class vault_client:
    def __init__(self, vault_addr=None, vault_token=None):
        """
        Sets the hvac client to communicate with Vault

        :param str vault_addr: the Vault server url
        :param str vault_token: the Vault token
        """
        self.client = None

        if not vault_addr or not vault_token:
            # logging.warning(
            #     "Vault server url or token missing. Looking for environment variables `VAULT_ADDR` and `VAULT_TOKEN`.")

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

    def get_datakey(self, vault_transit_keyring=None, mount_point=None):
        """
        Returns the payload for a new high-entropy key and the value encrypted with the named key.
        The data key is included in base64 encoded plaintext, and the ciphertext is used as reference 
        to re-obtain the derived key payload.

        :param str vault_transit_keyring: Name of the encryption key to use to encrypt the datakey
        :param str mount_point: The “path” on which the method/backend was mounted
        """
        if not vault_transit_keyring:
            # logging.warning(
            #     "Vault Transit keyring name missing. Looking for environment variable `VAULT_TRANSIT_KEYRING`.")

            if 'VAULT_TRANSIT_KEYRING' in os.environ:
                vault_transit_keyring = os.environ.get('VAULT_TRANSIT_KEYRING')
            else:
                logging.error(
                    "`VAULT_TRANSIT_KEYRING` must be set in your environment.")
                exit()

        if not mount_point:
            # logging.warning(
            #     "Vault Transit mountpoint is missing. Looking for environment variable `VAULT_MOUNTPOINT`.")

            if 'VAULT_MOUNTPOINT' in os.environ:
                mount_point = os.environ.get('VAULT_MOUNTPOINT')
            else:
                logging.error(
                    "`VAULT_MOUNTPOINT` must be set in your environment.")
                exit()

        response = None

        try:
            response = self.client.secrets.transit.generate_data_key(
                name=vault_transit_keyring,
                key_type='plaintext',
                mount_point=mount_point
            )
        except:
            logging.error("Unable to authenticate with Vault.")
            exit()

        return response

    def decrypt_datakey(self, ciphertext=None, vault_transit_keyring=None, mount_point=None):
        """
        Returns the payload for a new high-entropy key in plaintext.

        :param str ciphertext: Specifies the ciphertext to decrypt. This should be a part of the derived key payload.
        :param str vault_transit_keyring: Name of the encryption key to use to initially encrypt the datakey
        :param str mount_point: The “path” on which the method/backend was created
        """
        if not vault_transit_keyring:
            # logging.warning(
            #     "Vault Transit keyring name missing. Looking for environment variable `VAULT_TRANSIT_KEYRING`.")

            if 'VAULT_TRANSIT_KEYRING' in os.environ:
                vault_transit_keyring = os.environ.get('VAULT_TRANSIT_KEYRING')
            else:
                logging.error(
                    "`VAULT_TRANSIT_KEYRING` must be set in your environment.")
                exit()

        if not mount_point:
            # logging.warning(
            #     "Vault Transit mountpoint is missing. Looking for environment variable `VAULT_MOUNTPOINT`.")

            if 'VAULT_MOUNTPOINT' in os.environ:
                mount_point = os.environ.get('VAULT_MOUNTPOINT')
            else:
                logging.error(
                    "`VAULT_MOUNTPOINT` must be set in your environment.")
                exit()

        response = None

        try:
            response = self.client.secrets.transit.decrypt_data(
                name=vault_transit_keyring,
                ciphertext=ciphertext,
                mount_point=mount_point
            )
        except:
            logging.error("Unable to retreive DEK.")
            exit()

        return response


if __name__ == "__main__":

    VAULT_ADDR = os.environ.get('VAULT_ADDR', None)
    VAULT_TOKEN = os.environ.get('VAULT_TOKEN', None)
    VAULT_MOUNTPOINT = os.environ.get('VAULT_MOUNTPOINT', None)
    VAULT_TRANSIT_KEYRING = os.environ.get('VAULT_TRANSIT_KEYRING', None)

    if not VAULT_ADDR:
        logging.error(
            "`VAULT_ADDR` variable must be set in your environment.")
        exit()
    elif not VAULT_TOKEN:
        logging.error(
            "`VAULT_TOKEN` variable must be set in your environment.")
        exit()
    elif not VAULT_MOUNTPOINT:
        logging.error(
            "`VAULT_MOUNTPOINT` must be set in your environment.")
        exit()
    elif not VAULT_TRANSIT_KEYRING:
        logging.error(
            "`VAULT_TRANSIT_KEYRING` must be set in your environment.")
        exit()

    client = vault_client(VAULT_ADDR, VAULT_TOKEN)
    response = client.get_datakey(VAULT_TRANSIT_KEYRING, VAULT_MOUNTPOINT)

    pp = pprint.PrettyPrinter(indent=2)
    print(f"{bcolors.OKGREEN}\n\nData key request:\n{bcolors.ENDC}")
    pp.pprint(response)

    plaintext = response['data']['plaintext']
    ciphertext = response['data']['ciphertext']

    print(f"{bcolors.OKGREEN}\n\nData key recall:\n{bcolors.ENDC}")
    pp.pprint(client.decrypt_datakey(
        ciphertext, VAULT_TRANSIT_KEYRING, VAULT_MOUNTPOINT))
    print("\n")

    modulesToDelete = []
    for m in sys.modules:
        moduleName = str(m)
        if "myLibrary." in moduleName:
            modulesToDelete.append(moduleName)
    currentModule = __name__
    for mod in modulesToDelete:
        if mod != currentModule:  # Python cannot delete the current module
            del sys.modules[mod]
