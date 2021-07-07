import hvac
import os


def connect(vault_addr=None, vault_token=None):
    """
    Returns an hvac client to communicate with Vault

    :param str vault_addr: the vault server url
    :param str vault_token: the vault token
    """
    if not vault_addr or not vault_token:
        print("`VAULT_ADDR` and `VAULT_TOKEN` must be set in your environment.")
        exit()

    client = hvac.Client(
        url=vault_addr,
        token=vault_token,
        verify=True,
    )

    if not client.is_authenticated():
        print("Vault authentication failure.")
        client = None

    return client


def get_secret(client=None, vault_key_name=None):
    response = None
    try:
        response = client.secrets.transit.generate_data_key(
            name=vault_key_name,
            key_type='plaintext',
        )
    except:
        exit()

    return response


if __name__ == "__main__":

    VAULT_ADDR = None
    VAULT_TOKEN = None
    VAULT_ENDPOINT = None

    if "VAULT_ADDR" in os.environ and "VAULT_TOKEN" in os.environ and "VAULT_TRANSIT_KEYNAME":
        VAULT_ADDR = os.environ.get('VAULT_ADDR')
        VAULT_TOKEN = os.environ.get('VAULT_TOKEN')
        VAULT_TRANSIT_KEYNAME = os.environ.get('VAULT_TRANSIT_KEYNAME')

    client = connect(VAULT_ADDR, VAULT_TOKEN)
    response = get_secret(client, VAULT_TRANSIT_KEYNAME)

    plaintext = response['data']['plaintext']
    ciphertext = response['data']['ciphertext']

    print(plaintext, ciphertext)
