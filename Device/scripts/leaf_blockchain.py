# Public Information

LEAF_CHAIN_IDS = [1102, 1103]
LEAF_CHAIN_LEVEL = 2
PUBLIC_KEY_1102 = []
PUBLIC_KEY_1103 = []
ADDRESSES_1102 = []
ADDRESSES_1103 = []
IPS_1102 = []
IPS_1103 = []

INFO_1102 = [PUBLIC_KEY_1102, ADDRESSES_1102, IPS_1102]
INFO_1103 = [PUBLIC_KEY_1103, ADDRESSES_1103, IPS_1103]

CHAIN_ID_TO_LIST = {1102: INFO_1102, 1103: INFO_1103}


def get_leaf_chain_ids():
    return LEAF_CHAIN_IDS.copy()


def get_public_key_by_address(address, chain_id):
    return CHAIN_ID_TO_LIST[chain_id][0][CHAIN_ID_TO_LIST[chain_id][1].index(address)]


def address_exists(address, chain_id=1301):
    if address in CHAIN_ID_TO_LIST[chain_id][1]:
        return True
    return False


def get_addresses(chain_id):
    return CHAIN_ID_TO_LIST[chain_id][1].copy()


def get_addresses_length(chain_id):
    return len(CHAIN_ID_TO_LIST[chain_id][1])


def get_ips(chain_id):
    return CHAIN_ID_TO_LIST[chain_id][2].copy()


def get_ip_by_address(address, chain_id):
    return CHAIN_ID_TO_LIST[chain_id][2][CHAIN_ID_TO_LIST[chain_id][1].index(address)]
