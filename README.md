Software, libraries, and packages that need to be installed: `py-solc-x`, `web3`, `python-dotenv`, `nvm`, `nodejs`, `ganache@7.9.0`, `eth-brownie`, `cryptography`, `secp256k1`.

Configure your own blockchain in brownie's environment file `.brownie/network-config.yaml`, and then configure the blockchain name to be used in `networks: default:`.

The codes in the non-leaf_blockchain_nodes directory are used for nodes in non-leaf blockchains, while the codes in the leaf_blockchain_nodes directory are used for nodes in leaf blockchains. The two differ in the forwarding logic of group messages. In addition, leaf blockchain nodes need to participate in the management of group keys, while non-leaf blockchain nodes do not.

When starting a blockchain node, enter the corresponding node directory and do the following to start it:

1. Store the public information of the blockchain in the corresponding directory in `configdata`.
2. Run `brownie compile` through the administrator account to compile the smart contract
3. Run `brownie run scripts/run_app/deploy.py` through the administrator account to complete the deployment of the contract
4. For each node, start the node by running `brownie run scripts/run_app/listening`

The codes in the Device directory are used for IoT devices.

When starting the IoT device, enter the Device directory and start it by doing the following:

1. Store the device information in `configdata/device_info`
2. Execute `brownie run scripts/start_the_decie` to start the device
