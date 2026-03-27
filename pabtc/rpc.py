import decimal
import itertools
import pabtc.config
import pabtc.rate
import random
import requests
import typing


# Doc: https://developer.bitcoin.org/reference/rpc/


def call(method: str, params: list) -> typing.Any:
    if not hasattr(call, 'rate'):
        setattr(call, 'rate', pabtc.rate.Limits(pabtc.config.current.rpc.qps, 1))
    getattr(call, 'rate').wait(1)
    r = requests.post(pabtc.config.current.rpc.url, json={
        'id': random.randint(0x00000000, 0xffffffff),
        'jsonrpc': '2.0',
        'method': method,
        'params': params,
    }, auth=(
        pabtc.config.current.rpc.username,
        pabtc.config.current.rpc.password,
    )).json(parse_float=decimal.Decimal)
    if 'error' in r and r['error']:
        raise Exception(r['error'])
    return r['result']


def wait(txid: str):
    if pabtc.config.current == pabtc.config.develop:
        return
    for _ in itertools.repeat(0):
        r = get_raw_transaction(txid)
        if r['in_active_chain']:
            break

# =============================================================================
# Blockchain RPCs
# =============================================================================


def get_best_block_hash() -> str:
    return call('getbestblockhash', [])


def get_block(blockhash: str, verbosity: int = 1) -> dict:
    return call('getblock', [blockhash, verbosity])


def get_block_chain_info() -> dict:
    return call('getblockchaininfo', [])


def get_block_count() -> int:
    return call('getblockcount', [])


def get_block_filter(blockhash: str) -> dict:
    return call('getblockfilter', [blockhash])


def get_block_hash(height: int) -> str:
    return call('getblockhash', [height])


def get_block_header(blockhash: str) -> dict:
    return call('getblockheader', [blockhash])


def get_block_stats(hash_or_height: str | int) -> dict:
    return call('getblockstats', [hash_or_height])


def get_chain_tips() -> list[dict]:
    return call('getchaintips', [])


def get_chain_tx_stats(nblocks: int | None = None, blockhash: str | None = None) -> dict:
    return call('getchaintxstats', [nblocks, blockhash])


def get_difficulty() -> decimal.Decimal:
    return call('getdifficulty', [])


def get_mempool_ancestors(txid: str) -> list[str]:
    return call('getmempoolancestors', [txid])


def get_mempool_descendants(txid: str) -> list[str]:
    return call('getmempooldescendants', [txid])


def get_mempool_entry(txid: str) -> dict:
    return call('getmempoolentry', [txid])


def get_mempool_info() -> dict:
    return call('getmempoolinfo', [])


def get_raw_mempool() -> list[str]:
    return call('getrawmempool', [])


def get_tx_out(txid: str, vout: int) -> dict:
    return call('gettxout', [txid, vout])


def get_tx_out_proof(txids: list[str], blockhash: str | None = None) -> str:
    return call('gettxoutproof', [txids, blockhash])


def get_tx_out_set_info(hash_type: str | None = None) -> dict:
    return call('gettxoutsetinfo', [hash_type])


def precious_block(blockhash: str) -> None:
    return call('preciousblock', [blockhash])


def prune_blockchain(height: int) -> int:
    return call('pruneblockchain', [height])


def save_mempool() -> None:
    return call('savemempool', [])


def scan_tx_out_set(action: str, scanobjects: list[str]) -> dict:
    return call('scan_tx_out_set', [action, scanobjects])


def verify_chain(checklevel: int | None = None, nblocks: int | None = None) -> bool:
    return call('verifychain', [checklevel, nblocks])


def verify_tx_out_proof(proof: str) -> list[str]:
    return call('verifytxoutproof', [proof])

# =============================================================================
# Control RPCs
# =============================================================================


def get_memory_info(mode: str | None = None) -> str | dict:
    return call('getmemoryinfo', [mode])


def get_rpc_info() -> dict:
    return call('getrpcinfo', [])


def help() -> str:
    return call('help', [])


def logging(include: list[str], exclude: list[str]) -> dict:
    return call('logging', [include, exclude])


def stop() -> str:
    return call('stop', [])


def uptime() -> int:
    return call('uptime', [])

# =============================================================================
# Generating RPCs
# =============================================================================


def generate_block(output: str, transactions: list[str]) -> dict:
    return call('generateblock', [output, transactions])


def generate_to_address(nblocks: int, address: str) -> list[str]:
    return call('generatetoaddress', [nblocks, address])


def generate_to_descriptor(nblocks: int, descriptor: str) -> list[str]:
    return call('generatetodescriptor', [nblocks, descriptor])

# =============================================================================
# Mining RPCs
# =============================================================================


def get_block_template(template_request: dict) -> dict:
    return call('getblocktemplate', [template_request])


def get_mining_info() -> dict:
    return call('getmininginfo', [])


def get_network_hashps(nblocks: int | None = None, height: int | None = None) -> decimal.Decimal:
    return call('getnetworkhashps', [nblocks, height])


def prioritise_transaction(txid: str, fee_delta: int) -> bool:
    return call('prioritise_transaction', [txid, 0, fee_delta])


def submit_block(hexdata: str) -> None:
    return call('submitblock', [hexdata])


def submit_header(hexdata: str) -> None:
    return call('submitheader', [hexdata])

# =============================================================================
# Network RPCs
# =============================================================================


def addnode(node: str, command: str) -> None:
    return call('addnode', [node, command])


def clear_banned() -> None:
    return call('clearbanned', [])


def disconnect_node(address: str | None = None, nodeid: int | None = None) -> None:
    return call('disconnectnode', [address, nodeid])


def get_added_node_info(node: str | None = None) -> list[dict]:
    return call('getaddednodeinfo', [node])


def get_connection_count() -> int:
    return call('getconnectioncount', [])


def get_net_totals() -> dict:
    return call('getnettotals', [])


def get_network_info() -> dict:
    return call('getnetworkinfo', [])


def get_node_addresses() -> list[dict]:
    return call('getnodeaddresses', [])


def get_peer_info() -> list[dict]:
    return call('getpeerinfo', [])


def list_banned() -> list[dict]:
    return call('listbanned', [])


def ping() -> None:
    return call('ping', [])


def set_ban(subnet: str, command: str) -> None:
    return call('setban', [subnet, command])


def set_network_active(state: bool) -> bool:
    return call('setnetworkactive', [state])

# =============================================================================
# Rawtransactions RPCs
# =============================================================================


def analyze_psbt(psbt: str) -> dict:
    return call('analyzepsbt', [psbt])


def combine_psbt(txs: list[str]) -> str:
    return call('combinepsbt', [txs])


def combine_raw_transaction(txs: list[str]) -> str:
    return call('combinerawtransaction', [txs])


def convert_to_psbt(hexstring: str, permitsigdata: bool = False) -> str:
    return call('converttopsbt', [hexstring, permitsigdata])


def create_psbt(
    inputs: list[dict],
    outputs: list[dict],
    locktime: int = 0,
    replaceable: bool = False,
) -> str:
    return call('createpsbt', [inputs, outputs, locktime, replaceable])


def create_raw_transaction(
    inputs: list[dict],
    outputs: list[dict],
    locktime: int = 0,
    replaceable: bool = False,
) -> str:
    return call('createrawtransaction', [inputs, outputs, locktime, replaceable])


def decode_psbt(psbt: str) -> dict:
    return call('decodepsbt', [psbt])


def decode_raw_transaction(tx: str) -> dict:
    return call('decoderawtransaction', [tx])


def decode_script(hexstring: str) -> dict:
    return call('decodescript', [hexstring])


def finalize_psbt(psbt: str, extract: bool = True) -> dict:
    return call('finalizepsbt', [psbt, extract])


def fund_raw_transaction(hexstring: str, options: dict | None = None) -> dict:
    return call('fundrawtransaction', [hexstring, options])


def get_raw_transaction(txid: str) -> dict:
    return call('getrawtransaction', [txid, True])


def join_psbts(txs: list[str]) -> str:
    return call('joinpsbts', [txs])


def send_raw_transaction(tx: str) -> str:
    return call('sendrawtransaction', [tx])


def sign_raw_transaction_with_key(
    hexstring: str,
    privkeys: list[str],
    prevtxs: list[dict] = [],
    sighashtype: str = 'ALL',
) -> dict:
    return call('signrawtransactionwithkey', [hexstring, privkeys, prevtxs, sighashtype])


def test_mempool_accept(rawtxs: list[str]) -> list[dict]:
    return call('testmempoolaccept', [rawtxs])


def utxo_update_psbt(psbt: str, descriptors: list[dict] = []) -> str:
    return call('utxoupdatepsbt', [psbt, descriptors])

# =============================================================================
# Util RPCs
# =============================================================================


def create_multisig(nrequired: int, keys: list[str], address_type: str) -> dict:
    return call('createmultisig', [nrequired, keys, address_type])


def derive_addresses(descriptor: str, range: int | list[int]) -> list[str]:
    return call('deriveaddresses', [descriptor, range])


def estimate_smart_fee(conf_target: int) -> dict:
    # A mock is required on RegTest to allow this RPC to return meaningful data.
    # See: https://github.com/bitcoin/bitcoin/issues/11500
    if pabtc.config.current == pabtc.config.develop:
        return {'feerate': decimal.Decimal('0.00001'), 'blocks': conf_target}
    return call('estimatesmartfee', [conf_target, 'ECONOMICAL'])


def get_descriptor_info(descriptor: str) -> dict:
    return call('getdescriptorinfo', [descriptor])


def get_index_info(index_name: str | None = None) -> dict:
    return call('getindexinfo', [index_name])


def sign_message_with_privkey(prikey: str, message: str) -> str:
    return call('signmessagewithprivkey', [prikey, message])


def validate_address(address: str) -> dict:
    return call('validateaddress', [address])


def verify_message(address: str, signature: str, message: str) -> bool:
    return call('verifymessage', [address, signature, message])

# =============================================================================
# Wallet RPCs
# =============================================================================


def abandon_transaction(txid: str) -> None:
    return call('abandontransaction', [txid])


def abort_rescan() -> bool:
    return call('abortrescan', [])


def add_multisig_address(nrequired: int, keys: list[str], label: str, address_type: str) -> dict:
    return call('addmultisigaddress', [nrequired, keys, label, address_type])


def backup_wallet(destination: str) -> None:
    return call('backupwallet', [destination])


def bump_fee(txid: str, options: dict) -> dict:
    return call('bumpfee', [txid, options])


def create_wallet(
    wallet_name: str,
    disable_private_keys: bool = False,
    blank: bool = False,
    passphrase: str = '',
    avoid_reuse: bool = False,
    descriptors: bool = True,
    load_on_startup: bool | None = None,
    external_signer: bool = False,
) -> dict:
    return call('createwallet', [
        wallet_name,
        disable_private_keys,
        blank,
        passphrase,
        avoid_reuse,
        descriptors,
        load_on_startup,
        external_signer,
    ])


def dump_privkey(address: str) -> str:
    return call('dumpprivkey', [address])


def dump_wallet(filename: str) -> dict:
    return call('dumpwallet', [filename])


def encrypt_wallet(passphrase: str) -> str:
    return call('encryptwallet', [passphrase])


def get_addresses_by_label(label: str) -> dict:
    return call('getaddressesbylabel', [label])


def get_address_info(address: str) -> dict:
    return call('getaddressinfo', [address])


def get_balance(minconf: int = 0, include_watchonly: bool = False) -> decimal.Decimal:
    return call('getbalance', ['*', minconf, include_watchonly])


def get_balances() -> dict:
    return call('getbalances', [])


def get_new_address(label: str, address_type: str) -> str:
    return call('getnewaddress', [label, address_type])


def get_raw_change_address(address_type: str) -> str:
    return call('getrawchangeaddress', [address_type])


def get_received_by_address(address: str, minconf: int = 1) -> decimal.Decimal:
    return call('getreceivedbyaddress', [address, minconf])


def get_received_by_label(label: str, minconf: int = 1) -> decimal.Decimal:
    return call('getreceivedbylabel', [label, minconf])


def get_transaction(txid: str, include_watchonly: bool = False, verbose: bool = False) -> dict:
    return call('gettransaction', [txid, include_watchonly, verbose])


def get_unconfirmed_balance() -> decimal.Decimal:
    return call('getunconfirmedbalance', [])


def get_wallet_info() -> dict:
    return call('getwalletinfo', [])


def import_address(address: str, label: str, rescan: bool = True, p2sh: bool = False) -> None:
    return call('importaddress', [address, label, rescan, p2sh])


def import_descriptors(requests: list[dict]) -> list[dict]:
    return call('importdescriptors', [requests])


def import_multi(requests: list[dict], options: dict) -> list[dict]:
    return call('importmulti', [requests, options])


def import_privkey(privkey: str, label: str, rescan: bool = True) -> None:
    return call('importprivkey', [privkey, label, rescan])


def import_pruned_funds(rawtransaction: str, txoutproof: str) -> None:
    return call('importprunedfunds', [rawtransaction, txoutproof])


def import_pubkey(pubkey: str, label: str, rescan: bool = True) -> None:
    return call('importpubkey', [pubkey, label, rescan])


def import_wallet(filename: str) -> None:
    return call('importwallet', [filename])


def keypool_refill(newsize: int | None = None) -> None:
    return call('keypoolrefill', [newsize])


def list_address_groupings() -> list[list[list[str | decimal.Decimal]]]:
    return call('listaddressgroupings', [])


def list_labels(purpose: str | None = None) -> list[str]:
    return call('listlabels', [purpose])


def list_lock_unspent() -> list[dict]:
    return call('listlockunspent', [])


def list_received_by_address(
    minconf: int = 1,
    include_empty: bool = False,
    include_watchonly: bool = False,
    address_filter: str | None = None,
) -> list[dict]:
    return call('listreceivedbyaddress', [minconf, include_empty, include_watchonly, address_filter])


def list_received_by_label(
    minconf: int = 1,
    include_empty: bool = False,
    include_watchonly: bool = False,
) -> list[dict]:
    return call('listreceivedbylabel', [minconf, include_empty, include_watchonly])


def list_since_block(
    blockhash: str | None = None,
    target_confirmations: int = 1,
    include_watchonly: bool = False,
    include_removed: bool = True,
) -> dict:
    return call('listsinceblock', [blockhash, target_confirmations, include_watchonly, include_removed])


def list_transactions(
    label: str = '*',
    count: int = 10,
    skip: int = 0,
    include_watchonly: bool = False,
) -> list[dict]:
    return call('listtransactions', [label, count, skip, include_watchonly])


def list_unspent(addresses: list[str]) -> list:
    return call('listunspent', [0, 9999999, addresses])


def list_wallet_dir() -> dict:
    return call('listwalletdir', [])


def list_wallets() -> list[str]:
    return call('listwallets', [])


def load_wallet(filename: str, load_on_startup: bool | None = None) -> dict:
    return call('loadwallet', params=[filename, load_on_startup])


def lock_unspent(unlock: bool, transactions: list[dict]) -> bool:
    return call('lockunspent', params=[unlock, transactions])


def psbt_bump_fee(txid: str, options: dict | None = None) -> dict:
    return call('psbtbumpfee', [txid, options])


def remove_pruned_funds(txid: str) -> None:
    return call('removeprunedfunds', [txid])


def rescan_blockchain(start_height: int = 0, stop_height: int | None = None) -> dict:
    return call('rescanblockchain', [start_height, stop_height])


def send(
    outputs: dict,
    conf_target: int | None = None,
    estimate_mode: str = 'UNSET',
    fee_rate: decimal.Decimal | None = None,
    options: dict | None = None,
) -> dict:
    return call('send', [outputs, conf_target, estimate_mode, fee_rate, options])


def send_many(
    amounts: dict,
    minconf: int = 1,
    comment: str = '',
    subtractfeefrom: list[str] = [],
    replaceable: bool = False,
    conf_target: int | None = None,
    estimate_mode: str = 'UNSET',
    fee_rate: decimal.Decimal | None = None,
) -> str:
    return call('sendmany', [
        '',
        amounts,
        minconf,
        comment,
        subtractfeefrom,
        replaceable,
        conf_target,
        estimate_mode,
        fee_rate,
    ])


def send_to_address(
    address: str,
    amount: decimal.Decimal,
    comment: str = '',
    comment_to: str = '',
    subtractfeefromamount: bool = False,
    replaceable: bool = False,
    conf_target: int | None = None,
    estimate_mode: str = 'UNSET',
    avoid_reuse: bool = True,
    fee_rate: decimal.Decimal | None = None,
) -> str:
    return call('sendtoaddress', [
        address,
        amount,
        comment,
        comment_to,
        subtractfeefromamount,
        replaceable,
        conf_target,
        estimate_mode,
        avoid_reuse,
        fee_rate,
    ])


def set_hd_seed(newkeypool: bool = True, seed: str | None = None) -> None:
    return call('sethdseed', [newkeypool, seed])


def set_label(address: str, label: str) -> None:
    return call('setlabel', [address, label])


def set_tx_fee(amount: decimal.Decimal) -> bool:
    return call('settxfee', [amount])


def set_wallet_flag(flag: str, value: bool = True) -> dict:
    return call('setwalletflag', [flag, value])


def sign_message(address: str, message: str) -> str:
    return call('signmessage', [address, message])


def sign_raw_transaction_with_wallet(
    hexstring: str,
    prevtxs: list[dict] = [],
    sighashtype: str = 'ALL',
) -> dict:
    return call('signrawtransactionwithwallet', [hexstring, prevtxs, sighashtype])


def unload_wallet(
    wallet_name: str | None = None,
    load_on_startup: bool | None = None,
) -> dict:
    return call('unloadwallet', [wallet_name, load_on_startup])


def upgrade_wallet(version: int | None = None) -> dict:
    return call('upgradewallet', [version])


def wallet_create_funded_psbt(
    inputs: list[dict],
    outputs: list[dict],
    locktime: int = 0,
    options: dict | None = None,
    bip32derivs: bool = True,
) -> dict:
    return call('walletcreatefundedpsbt', [inputs, outputs, locktime, options, bip32derivs])


def wallet_lock() -> None:
    return call('walletlock', [])


def wallet_passphrase(passphrase: str, timeout: int) -> None:
    return call('walletpassphrase', [passphrase, timeout])


def wallet_passphrase_change(oldpassphrase: str, newpassphrase: str) -> None:
    return call('walletpassphrasechange', [oldpassphrase, newpassphrase])


def wallet_process_psbt(
    psbt: str,
    sign: bool = True,
    sighashtype: str = 'ALL',
    bip32derivs: bool = True,
) -> dict:
    return call('walletprocesspsbt', [psbt, sign, sighashtype, bip32derivs])
