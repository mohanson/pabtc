import decimal
import itertools
import pabtc.config
import pabtc.rate
import random
import requests
import typing


# Doc: https://developer.bitcoin.org/reference/rpc/


def call(method: str, params: typing.List[typing.Any]) -> typing.Any:
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


def get_block(blockhash: str, verbosity: int = 1) -> typing.Dict:
    return call('getblock', [blockhash, verbosity])


def get_block_chain_info() -> typing.Dict:
    return call('getblockchaininfo', [])


def get_block_count() -> int:
    return call('getblockcount', [])


def get_block_filter(blockhash: str) -> typing.Dict:
    return call('getblockfilter', [blockhash])


def get_block_hash(height: int) -> str:
    return call('getblockhash', [height])


def get_block_header(blockhash: str) -> typing.Dict:
    return call('getblockheader', [blockhash])


def get_block_stats(hash_or_height: typing.Union[str, int]) -> typing.Dict:
    return call('getblockstats', [hash_or_height])


def get_chain_tips() -> typing.List[typing.Dict]:
    return call('getchaintips', [])


def get_chain_tx_stats(nblocks: typing.Optional[int] = None, blockhash: typing.Optional[str] = None) -> typing.Dict:
    return call('getchaintxstats', [nblocks, blockhash])


def get_difficulty() -> decimal.Decimal:
    return call('getdifficulty', [])


def get_mempool_ancestors(txid: str) -> typing.List[str]:
    return call('getmempoolancestors', [txid])


def get_mempool_descendants(txid: str) -> typing.List[str]:
    return call('getmempooldescendants', [txid])


def get_mempool_entry(txid: str) -> typing.Dict:
    return call('getmempoolentry', [txid])


def get_mempool_info() -> typing.Dict:
    return call('getmempoolinfo', [])


def get_raw_mempool() -> typing.List[str]:
    return call('getrawmempool', [])


def get_tx_out(txid: str, vout: int) -> typing.Dict:
    return call('gettxout', [txid, vout])


def get_tx_out_proof(txids: typing.List[str], blockhash: typing.Optional[str] = None) -> str:
    return call('gettxoutproof', [txids, blockhash])


def get_tx_out_set_info(hash_type: typing.Optional[str] = None) -> typing.Dict:
    return call('gettxoutsetinfo', [hash_type])


def precious_block(blockhash: str) -> None:
    return call('preciousblock', [blockhash])


def prune_blockchain(height: int) -> int:
    return call('pruneblockchain', [height])


def save_mempool() -> None:
    return call('savemempool', [])


def scan_tx_out_set(action: str, scanobjects: typing.List[str]) -> typing.Dict:
    return call('scan_tx_out_set', [action, scanobjects])


def verify_chain(checklevel: typing.Optional[int] = None, nblocks: typing.Optional[int] = None) -> bool:
    return call('verifychain', [checklevel, nblocks])


def verify_tx_out_proof(proof: str) -> typing.List[str]:
    return call('verifytxoutproof', [proof])

# =============================================================================
# Control RPCs
# =============================================================================


def get_memory_info(mode: typing.Optional[str] = None) -> typing.Union[str, typing.Dict]:
    return call('getmemoryinfo', [mode])


def get_rpc_info() -> typing.Dict:
    return call('getrpcinfo', [])


def help() -> str:
    return call('help', [])


def logging(include: typing.List[str], exclude: typing.List[str]) -> typing.Dict:
    return call('logging', [include, exclude])


def stop() -> str:
    return call('stop', [])


def uptime() -> int:
    return call('uptime', [])

# =============================================================================
# Generating RPCs
# =============================================================================


def generate_block(output: str, transactions: typing.List[str]) -> typing.Dict:
    return call('generateblock', [output, transactions])


def generate_to_address(nblocks: int, address: str) -> typing.List[str]:
    return call('generatetoaddress', [nblocks, address])


def generate_to_descriptor(nblocks: int, descriptor: str) -> typing.List[str]:
    return call('generatetodescriptor', [nblocks, descriptor])

# =============================================================================
# Mining RPCs
# =============================================================================


def get_block_template(template_request: typing.Dict) -> typing.Dict:
    return call('getblocktemplate', [template_request])


def get_mining_info() -> typing.Dict:
    return call('getmininginfo', [])


def get_network_hashps(nblocks: typing.Optional[int] = None, height: typing.Optional[int] = None) -> decimal.Decimal:
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


def disconnect_node(address: typing.Optional[str] = None, nodeid: typing.Optional[int] = None) -> None:
    return call('disconnectnode', [address, nodeid])


def get_added_node_info(node: typing.Optional[str] = None) -> typing.List[typing.Dict]:
    return call('getaddednodeinfo', [node])


def get_connection_count() -> int:
    return call('getconnectioncount', [])


def get_net_totals() -> typing.Dict:
    return call('getnettotals', [])


def get_network_info() -> typing.Dict:
    return call('getnetworkinfo', [])


def get_node_addresses() -> typing.List[typing.Dict]:
    return call('getnodeaddresses', [])


def get_peer_info() -> typing.List[typing.Dict]:
    return call('getpeerinfo', [])


def list_banned() -> typing.List[typing.Dict]:
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


def analyze_psbt(psbt: str) -> typing.Dict:
    return call('analyzepsbt', [psbt])


def combine_psbt(txs: typing.List[str]) -> str:
    return call('combinepsbt', [txs])


def combine_raw_transaction(txs: typing.List[str]) -> str:
    return call('combinerawtransaction', [txs])


def convert_to_psbt(hexstring: str, permitsigdata: bool = False) -> str:
    return call('converttopsbt', [hexstring, permitsigdata])


def create_psbt(
    inputs: typing.List[typing.Dict],
    outputs: typing.List[typing.Dict],
    locktime: int = 0,
    replaceable: bool = False,
) -> str:
    return call('createpsbt', [inputs, outputs, locktime, replaceable])


def create_raw_transaction(
    inputs: typing.List[typing.Dict],
    outputs: typing.List[typing.Dict],
    locktime: int = 0,
    replaceable: bool = False,
) -> str:
    return call('createrawtransaction', [inputs, outputs, locktime, replaceable])


def decode_psbt(psbt: str) -> typing.Dict:
    return call('decodepsbt', [psbt])


def decode_raw_transaction(tx: str) -> typing.Dict:
    return call('decoderawtransaction', [tx])


def decode_script(hexstring: str) -> typing.Dict:
    return call('decodescript', [hexstring])


def finalize_psbt(psbt: str, extract: bool = True) -> typing.Dict:
    return call('finalizepsbt', [psbt, extract])


def fund_raw_transaction(hexstring: str, options: typing.Optional[typing.Dict] = None) -> typing.Dict:
    return call('fundrawtransaction', [hexstring, options])


def get_raw_transaction(txid: str) -> typing.Dict:
    return call('getrawtransaction', [txid, True])


def join_psbts(txs: typing.List[str]) -> str:
    return call('joinpsbts', [txs])


def send_raw_transaction(tx: str) -> str:
    return call('sendrawtransaction', [tx])


def sign_raw_transaction_with_key(
    hexstring: str,
    privkeys: typing.List[str],
    prevtxs: typing.Optional[typing.List[typing.Dict]] = None,
    sighashtype: str = 'ALL',
) -> typing.Dict:
    return call('signrawtransactionwithkey', [hexstring, privkeys, prevtxs, sighashtype])


def test_mempool_accept(rawtxs: typing.List[str]) -> typing.List[typing.Dict]:
    return call('testmempoolaccept', [rawtxs])


def utxo_update_psbt(psbt: str, descriptors: typing.Optional[typing.List[typing.Dict]] = None) -> str:
    return call('utxoupdatepsbt', [psbt, descriptors])

# =============================================================================
# Util RPCs
# =============================================================================


def create_multisig(nrequired: int, keys: typing.List[str], address_type: str) -> typing.Dict:
    return call('createmultisig', [nrequired, keys, address_type])


def derive_addresses(descriptor: str, range: typing.Union[int, typing.List[int]]) -> typing.List[str]:
    return call('deriveaddresses', [descriptor, range])


def estimate_smart_fee(conf_target: int) -> typing.Dict:
    # A mock is required on RegTest to allow this RPC to return meaningful data.
    # See: https://github.com/bitcoin/bitcoin/issues/11500
    if pabtc.config.current == pabtc.config.develop:
        return {'feerate': decimal.Decimal('0.00001'), 'blocks': conf_target}
    return call('estimatesmartfee', [conf_target, 'ECONOMICAL'])


def get_descriptor_info(descriptor: str) -> typing.Dict:
    return call('getdescriptorinfo', [descriptor])


def get_index_info(index_name: typing.Optional[str] = None) -> typing.Dict:
    return call('getindexinfo', [index_name])


def sign_message_with_privkey(prikey: str, message: str) -> str:
    return call('signmessagewithprivkey', [prikey, message])


def validate_address(address: str) -> typing.Dict:
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


def add_multisig_address(nrequired: int, keys: typing.List[str], label: str, address_type: str) -> typing.Dict:
    return call('addmultisigaddress', [nrequired, keys, label, address_type])


def backup_wallet(destination: str) -> None:
    return call('backupwallet', [destination])


def bump_fee(txid: str, options: typing.Dict) -> typing.Dict:
    return call('bumpfee', [txid, options])


def create_wallet(
    wallet_name: str,
    disable_private_keys: bool = False,
    blank: bool = False,
    passphrase: str = '',
    avoid_reuse: bool = False,
    descriptors: bool = True,
    load_on_startup: typing.Optional[bool] = None,
    external_signer: bool = False,
) -> typing.Dict:
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


def dump_wallet(filename: str) -> typing.Dict:
    return call('dumpwallet', [filename])


def encrypt_wallet(passphrase: str) -> str:
    return call('encryptwallet', [passphrase])


def get_addresses_by_label(label: str) -> typing.Dict:
    return call('getaddressesbylabel', [label])


def get_address_info(address: str) -> typing.Dict:
    return call('getaddressinfo', [address])


def get_balance(minconf: int = 0, include_watchonly: bool = False) -> decimal.Decimal:
    return call('getbalance', ['*', minconf, include_watchonly])


def get_balances() -> typing.Dict:
    return call('getbalances', [])


def get_new_address(label: str, address_type: str) -> str:
    return call('getnewaddress', [label, address_type])


def get_raw_change_address(address_type: str) -> str:
    return call('getrawchangeaddress', [address_type])


def get_received_by_address(address: str, minconf: int = 1) -> decimal.Decimal:
    return call('getreceivedbyaddress', [address, minconf])


def get_received_by_label(label: str, minconf: int = 1) -> decimal.Decimal:
    return call('getreceivedbylabel', [label, minconf])


def get_transaction(txid: str, include_watchonly: bool = False, verbose: bool = False) -> typing.Dict:
    return call('gettransaction', [txid, include_watchonly, verbose])


def get_unconfirmed_balance() -> decimal.Decimal:
    return call('getunconfirmedbalance', [])


def get_wallet_info() -> typing.Dict:
    return call('getwalletinfo', [])


def import_address(address: str, label: str, rescan: bool = True, p2sh: bool = False) -> None:
    return call('importaddress', [address, label, rescan, p2sh])


def import_descriptors(requests: typing.List[typing.Dict]) -> typing.List[typing.Dict]:
    return call('importdescriptors', [requests])


def import_multi(requests: typing.List[typing.Dict], options: typing.Dict) -> typing.List[typing.Dict]:
    return call('importmulti', [requests, options])


def import_privkey(privkey: str, label: str, rescan: bool = True) -> None:
    return call('importprivkey', [privkey, label, rescan])


def import_pruned_funds(rawtransaction: str, txoutproof: str) -> None:
    return call('importprunedfunds', [rawtransaction, txoutproof])


def import_pubkey(pubkey: str, label: str, rescan: bool = True) -> None:
    return call('importpubkey', [pubkey, label, rescan])


def import_wallet(filename: str) -> None:
    return call('importwallet', [filename])


def keypool_refill(newsize: typing.Optional[int] = None) -> None:
    return call('keypoolrefill', [newsize])


def list_address_groupings() -> typing.List[typing.List[typing.List[typing.Union[str, decimal.Decimal]]]]:
    return call('listaddressgroupings', [])


def list_labels(purpose: typing.Optional[str] = None) -> typing.List[str]:
    return call('listlabels', [purpose])


def list_lock_unspent() -> typing.List[typing.Dict]:
    return call('listlockunspent', [])


def list_received_by_address(
    minconf: int = 1,
    include_empty: bool = False,
    include_watchonly: bool = False,
    address_filter: typing.Optional[str] = None,
) -> typing.List[typing.Dict]:
    return call('listreceivedbyaddress', [minconf, include_empty, include_watchonly, address_filter])


def list_received_by_label(
    minconf: int = 1,
    include_empty: bool = False,
    include_watchonly: bool = False,
) -> typing.List[typing.Dict]:
    return call('listreceivedbylabel', [minconf, include_empty, include_watchonly])


def list_since_block(
    blockhash: typing.Optional[str] = None,
    target_confirmations: int = 1,
    include_watchonly: bool = False,
    include_removed: bool = True,
) -> typing.Dict:
    return call('listsinceblock', [blockhash, target_confirmations, include_watchonly, include_removed])


def list_transactions(
    label: str = '*',
    count: int = 10,
    skip: int = 0,
    include_watchonly: bool = False,
) -> typing.List[typing.Dict]:
    return call('listtransactions', [label, count, skip, include_watchonly])


def list_unspent(addresses: typing.List[str]) -> typing.List:
    return call('listunspent', [0, 9999999, addresses])


def list_wallet_dir() -> typing.Dict:
    return call('listwalletdir', [])


def list_wallets() -> typing.List[str]:
    return call('listwallets', [])


def load_wallet(filename: str, load_on_startup: typing.Optional[bool] = None) -> typing.Dict:
    return call('loadwallet', params=[filename, load_on_startup])


def lock_unspent(unlock: bool, transactions: typing.Optional[typing.List[typing.Dict]] = None) -> bool:
    return call('lockunspent', params=[unlock, transactions])


def psbt_bump_fee(txid: str, options: typing.Optional[typing.Dict] = None) -> typing.Dict:
    return call('psbtbumpfee', [txid, options])


def remove_pruned_funds(txid: str) -> None:
    return call('removeprunedfunds', [txid])


def rescan_blockchain(start_height: int = 0, stop_height: typing.Optional[int] = None) -> typing.Dict:
    return call('rescanblockchain', [start_height, stop_height])


def send(
    outputs: typing.Dict,
    conf_target: typing.Optional[int] = None,
    estimate_mode: str = 'UNSET',
    fee_rate: typing.Optional[decimal.Decimal] = None,
    options: typing.Optional[typing.Dict] = None,
) -> typing.Dict:
    return call('send', [outputs, conf_target, estimate_mode, fee_rate, options])


def send_many(
    amounts: typing.Dict,
    minconf: int = 1,
    comment: str = '',
    subtractfeefrom: typing.Optional[typing.List[str]] = None,
    replaceable: bool = False,
    conf_target: typing.Optional[int] = None,
    estimate_mode: str = 'UNSET',
    fee_rate: typing.Optional[decimal.Decimal] = None,
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
    conf_target: typing.Optional[int] = None,
    estimate_mode: str = 'UNSET',
    avoid_reuse: bool = True,
    fee_rate: typing.Optional[decimal.Decimal] = None,
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


def set_hd_seed(newkeypool: bool = True, seed: typing.Optional[str] = None) -> None:
    return call('sethdseed', [newkeypool, seed])


def set_label(address: str, label: str) -> None:
    return call('setlabel', [address, label])


def set_tx_fee(amount: decimal.Decimal) -> bool:
    return call('settxfee', [amount])


def set_wallet_flag(flag: str, value: bool = True) -> typing.Dict:
    return call('setwalletflag', [flag, value])


def sign_message(address: str, message: str) -> str:
    return call('signmessage', [address, message])


def sign_raw_transaction_with_wallet(
    hexstring: str,
    prevtxs: typing.Optional[typing.List[typing.Dict]] = None,
    sighashtype: str = 'ALL',
) -> typing.Dict:
    return call('signrawtransactionwithwallet', [hexstring, prevtxs, sighashtype])


def unload_wallet(
    wallet_name: typing.Optional[str] = None,
    load_on_startup: typing.Optional[bool] = None,
) -> typing.Dict:
    return call('unloadwallet', [wallet_name, load_on_startup])


def upgrade_wallet(version: typing.Optional[int] = None) -> typing.Dict:
    return call('upgradewallet', [version])


def wallet_create_funded_psbt(
    inputs: typing.List[typing.Dict],
    outputs: typing.List[typing.Dict],
    locktime: int = 0,
    options: typing.Optional[typing.Dict] = None,
    bip32derivs: bool = True,
) -> typing.Dict:
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
) -> typing.Dict:
    return call('walletprocesspsbt', [psbt, sign, sighashtype, bip32derivs])
