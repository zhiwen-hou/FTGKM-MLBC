ADJACENT_CHAINS_NAMES = ["son1102", "son1103"]
ADJACENT_CHAINS_IDS = [1102, 1103]
SELF_CHAIN_ID = 1101


def get_adjacent_chain_ids():
    return ADJACENT_CHAINS_IDS.copy()


def get_adjacent_chain_name_by_id(adjacent_chain_id):
    return ADJACENT_CHAINS_NAMES[ADJACENT_CHAINS_IDS.index(adjacent_chain_id)]


def get_adjacent_chain_id_by_name(adjacent_chain_name):
    return ADJACENT_CHAINS_IDS[ADJACENT_CHAINS_NAMES.index(adjacent_chain_name)]


def chian_id_exists(chain_id):
    if chain_id in ADJACENT_CHAINS_IDS:
        return True
    return False


def chain_name_exists(chain_name):
    if chain_name in ADJACENT_CHAINS_NAMES:
        return True
    return False
