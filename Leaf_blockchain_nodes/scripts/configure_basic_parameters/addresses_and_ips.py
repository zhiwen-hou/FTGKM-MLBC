# This file is used to obtain address and other information during testing

# Fill in the relevant blockchain node address
SELF_ADDRESSES = []
PARENT_ADDRESSES = []

# Fill in the IP address of the relevant node
SELF_IPS = []
PARENT_IPS = []

# Enter the CA address
CA_ADDRESSES = []

SELF_ADDRESSES_AND_IPS = [SELF_ADDRESSES, SELF_IPS]
PARENT_ADDRESSES_AND_IPS = [PARENT_ADDRESSES, PARENT_IPS]
CA_LIST = [CA_ADDRESSES]

CHAIN_NAME_TO_LIST = {
    "self": SELF_ADDRESSES_AND_IPS,
    "parent": PARENT_ADDRESSES_AND_IPS,
    "ca": CA_LIST,
}


def address_exists(address, chain_name="self"):
    if address in CHAIN_NAME_TO_LIST[chain_name][0]:
        return True
    return False


def get_addresses(chain_name="self"):
    return CHAIN_NAME_TO_LIST[chain_name][0].copy()


def get_addresses_length(chain_name="self"):
    return len(CHAIN_NAME_TO_LIST[chain_name][0])


def get_ips(chain_name="self"):
    return CHAIN_NAME_TO_LIST[chain_name][1].copy()


def get_ip_by_address(address, chain_name="self"):
    return CHAIN_NAME_TO_LIST[chain_name][1][
        CHAIN_NAME_TO_LIST[chain_name][0].index(address)
    ]
