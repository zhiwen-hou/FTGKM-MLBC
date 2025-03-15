# Storing information in the blockchain

from brownie import GroupKeyManagement
import datetime


def store_group_key(
    received_data,
    group_key_hash,
    self_chain_addresses,
    encrypted_group_keys,
    account,
    lock,
):
    group_key_management = GroupKeyManagement[-1]
    try:
        with lock:
            # nonce = web3.eth.get_transaction_count(account.address)
            if received_data[0] == "join group":
                group_key_management.deviceJoinGroup(
                    received_data[0],
                    received_data[1],
                    received_data[2],
                    received_data[3],
                    group_key_hash,
                    self_chain_addresses,
                    encrypted_group_keys,
                    {"from": account, "required_confs": 0},
                )
            elif received_data[0] == "leave group":
                group_key_management.deviceLeaveGroup(
                    received_data[0],
                    received_data[1],
                    received_data[2],
                    group_key_hash,
                    self_chain_addresses,
                    encrypted_group_keys,
                    {"from": account, "required_confs": 0},
                )
            elif received_data[0] == "cert invalid":
                group_key_management.deviceCertInvalid(
                    received_data[0],
                    received_data[1],
                    group_key_hash,
                    self_chain_addresses,
                    encrypted_group_keys,
                    {"from": account, "required_confs": 0},
                )
            elif received_data[0] == "address changed":
                group_key_management.deviceCertInvalid(
                    group_key_hash,
                    self_chain_addresses,
                    encrypted_group_keys,
                    {"from": account, "required_confs": 0},
                )
    except Exception as e:
        if (
            str(e).find("The device has joined the group") == -1
            and str(e).find("There are incorrect signer") == -1
            and str(e).find("No invalid cert found") == -1
        ):
            print(
                f"{int(datetime.datetime.today().timestamp())} GroupKeyManagement's error: {e}"
            )
