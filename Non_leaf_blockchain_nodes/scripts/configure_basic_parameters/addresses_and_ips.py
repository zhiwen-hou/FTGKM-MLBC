SELF_ADDRESSES = []
SON1102_ADDRESSES = []
SON1103_ADDRESSES = []

SELF_IPS = []
SON1102_IPS = []
SON1103_IPS = []

SELF_ADDRESSES_AND_IPS = [SELF_ADDRESSES, SELF_IPS]
SON1102_ADDRESSES_AND_IPS = [SON1102_ADDRESSES, SON1102_IPS]
SON1103_ADDRESSES_AND_IPS = [SON1103_ADDRESSES, SON1103_IPS]

CHAIN_NAME_TO_LIST = {
    "self": SELF_ADDRESSES_AND_IPS,
    "son1102": SON1102_ADDRESSES_AND_IPS,
    "son1103": SON1103_ADDRESSES_AND_IPS,
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
