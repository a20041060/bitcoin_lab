#!/usr/bin/env python3

# Based on spend-p2sh-txout.py from python-bitcoinlib.
# Copyright (C) 2017 Mengling LIU

import os
import subprocess
import json

import sys
if sys.version_info.major < 3:
    sys.stderr.write('Sorry, Python 3.x required by this example.\n')
    sys.exit(1)

import bitcoin
import bitcoin.rpc
from bitcoin import SelectParams
from bitcoin.core import b2x, lx, b2lx, COIN, COutPoint, CMutableTxOut, CMutableTxIn, CMutableTransaction, Hash160
from bitcoin.core.script import CScript, OP_DUP, OP_IF, OP_ELSE, OP_ENDIF, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, SignatureHash, SIGHASH_ALL
from bitcoin.core.script import OP_DROP, OP_CHECKLOCKTIMEVERIFY, OP_SHA256, OP_TRUE
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret

import hashlib

# Before you run this code, you should complete the following tasks first,
# 1. Run a bitcoin node in regtest mode
# 2. Create a wallet
# 3. Mining blocks to receiving bitcoins
# 4. Set the transaction fee/kB for your wallet
SelectParams('regtest')
proxy = bitcoin.rpc.Proxy()

# Get a new address for Bob to receive bitcoins
bobaddress = proxy.getnewaddress()
print("Bob address:", str(bobaddress))

# Dump the private key for Bob to generate a signature later
seckey = proxy.dumpprivkey(bobaddress)

# Create a hash value to construct redeem script
preimage = bytes.fromhex("107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f")
h = hashlib.sha256(preimage).digest()

# Construct a redeem script for P2SH 

#######################################
##You should complete this part based on the spending rule described in the assignment.  
txin_redeemScript = CScript([OP_SHA256, h, OP_EQUALVERIFY, OP_DUP, OP_HASH160,
                             bobaddress, OP_EQUALVERIFY, OP_CHECKSIG])

print("Redeem script:", b2x(txin_redeemScript))
#######################################

# Create P2SH scriptPubKey from the redeem script you construct.
txin_scriptPubKey = txin_redeemScript.to_p2sh_scriptPubKey()
print("P2SH scriptPubKey", b2x(txin_scriptPubKey))

# Convert the P2SH scriptPubKey to a base58 Bitcoin address
txin_p2sh_address = CBitcoinAddress.from_scriptPubKey(txin_scriptPubKey)
p2sh = str(txin_p2sh_address)
print('P2SH address:', p2sh)

# Create a transaction sending bitcoins to P2SH address
amount = 1.0*COIN
fund_tx = proxy.sendtoaddress(txin_p2sh_address, amount)
print('Transaction ID:', b2x(lx(b2x(fund_tx))))
print('Raw fund_tx', fund_tx) 

txinfo = proxy.gettransaction(fund_tx)
details = txinfo['details'][0]
vout = details['vout']

print('Transaction Details:', details)
print('Bob address:', bobaddress)
print('Bob secret key:', seckey)
print('preimage hex:', "107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f")

def generate_current_getblock():
    proc = subprocess.Popen(["bitcoin-cli -regtest -generate", "1"], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    block = "".join(json.loads(out)['blocks'])
    os.system('bitcoin-cli -regtest getblock ' + block + " 2")

generate_current_getblock()

print("---------------Q4---------------")
# Create the txin structure. scriptSig defaults to being empty.
# The input is the p2sh funding transaction txid, vout is its index
txin = CMutableTxIn(COutPoint(fund_tx, vout))

# Create the txout. Pays out to recipient, so uses recipient's pubkey
# Withdraw full amount minus fee
default_fee = 0.00001*COIN
txout = CMutableTxOut(amount - default_fee, bobaddress.to_scriptPubKey())

# Create the unsigned raw transaction.
tx = CMutableTransaction([txin], [txout])

# Calculate the signature hash for that transaction. Note how the script we use
# is the redeemScript, not the scriptPubKey. EvalScript() will be evaluating the redeemScript
sighash = SignatureHash(txin_redeemScript, tx, 0, SIGHASH_ALL)

# Now sign it. We have to append the type of signature we want to the end, in
# this case the usual SIGHASH_ALL.
sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])

# Set the scriptSig of our transaction input appropriately to complete the challenge.
txin.scriptSig = CScript([ sig, seckey.pub, preimage, txin_redeemScript])

print("Redeem tx hex:", b2x(tx.serialize()))

# Verify the signature worked.
VerifyScript(txin.scriptSig, txin_scriptPubKey, tx, 0, (SCRIPT_VERIFY_P2SH,))

print("Now sending redeem transaction.......")
txid = proxy.sendrawtransaction(tx)
print("Txid of submitted redeem tx: ", b2x(lx(b2x(txid))))

generate_current_getblock()