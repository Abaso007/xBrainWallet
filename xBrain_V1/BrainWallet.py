import codecs , random , hashlib , ecdsa , sys , time
from time import sleep
from lxml import html
import requests
from colorama import Fore , Style


def xBal(address):
    urlblock = f"https://bitcoin.atomicwallet.io/address/{address}"
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    treetxid = source_code.xpath(xpatch_txid)
    return str(treetxid[0].text_content())


def xTX(address):
    urlblock = f"https://bitcoin.atomicwallet.io/address/{address}"
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    treetxid = source_code.xpath(xpatch_txid)
    return str(treetxid[0].text_content())


mylist = []

with open('AlphaWords.txt' , newline = '' , encoding = 'utf-8') as f:
    mylist.extend(line.strip() for line in f)


class xWallet :

    @staticmethod
    def generate_address_from_passphrase(passphrase):
        private_key = hashlib.sha256(passphrase.encode('utf-8')).hexdigest()
        address = xWallet.generate_address_from_private_key(private_key)
        return private_key , address

    @staticmethod
    def generate_address_from_private_key(private_key):
        public_key = xWallet.__private_to_public(private_key)
        return xWallet.__public_to_address(public_key)

    @staticmethod
    def __private_to_public(private_key):
        private_key_bytes = codecs.decode(private_key , 'hex')
        key = ecdsa.SigningKey.from_string(
                private_key_bytes , curve = ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes , 'hex')
        bitcoin_byte = b'04'
        return bitcoin_byte + key_hex

    @staticmethod
    def __public_to_address(public_key):
        PublicKeyByte = codecs.decode(public_key , 'hex')
        sha256_bpk = hashlib.sha256(PublicKeyByte)
        sha256_bpk_digest = sha256_bpk.digest()
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest , 'hex')
        NetByte = b'00'
        NetBTCBytePubKey = NetByte + ripemd160_bpk_hex
        NetBTCPubKeyByte = codecs.decode(
                NetBTCBytePubKey , 'hex')
        Hash256N = hashlib.sha256(NetBTCPubKeyByte)
        Hash256N_digest = Hash256N.digest()
        sha256_2_nbpk = hashlib.sha256(Hash256N_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest , 'hex')
        checksum = sha256_2_hex[:8]
        addrHex = (NetBTCBytePubKey + checksum).decode('utf-8')
        return xWallet.base58(addrHex)

    @staticmethod
    def base58(addrHex):
        alpha = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        BaseStr58 = ''
        LanZeros = len(addrHex) - len(addrHex.lstrip('0'))
        AddrINT = int(addrHex , 16)
        while AddrINT > 0 :
            digit = AddrINT % 58
            dgChar = alpha[digit]
            BaseStr58 = dgChar + BaseStr58
            AddrINT //= 58
        ones = LanZeros // 2
        for _ in range(ones):
            BaseStr58 = f'1{BaseStr58}'
        return BaseStr58


z = 0
w = 0
s = 0
ifbtc = '0 BTC'
for i in range(len(mylist)):

    passphrase = mylist[i]
    wallet = xWallet()
    private_key , address = wallet.generate_address_from_passphrase(passphrase)
    dec = int(private_key , 16)
    bal = xBal(address)
    txid = xTX(address)
    print(
        Fore.YELLOW,
        'Check:',
        Fore.WHITE,
        z,
        Fore.YELLOW,
        'Win:',
        Fore.GREEN,
        w,
        Fore.YELLOW,
        ' Address:',
        Fore.RED,
        address,
        Fore.GREEN,
        ' TX:',
        Fore.WHITE,
        txid,
    )
    print(Fore.YELLOW, 'PrivateKey:', Fore.RED, private_key)
    print(
        f'{Fore.BLUE}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~({Fore.YELLOW} M M D R Z A . C o M {Fore.BLUE}'
        + ')~~~~~~~~~~~~~~~~~~~~~~~~~~\n'
    )

    z += 1
    if int(txid) > 0:
        w += 1
        print(
            Fore.RED,
            'Scan No:',
            Fore.YELLOW,
            z,
            Fore.RED,
            ' Win No:',
            Fore.WHITE,
            w,
            Fore.GREEN,
            ' Address:',
            Fore.YELLOW,
            address,
        )
        print(
            Fore.BLUE,
            'PrivateKey:',
            Fore.MAGENTA,
            private_key,
            Fore.BLUE,
            '              BAL:',
            Fore.WHITE,
            bal,
        )
        print('--------------------------------[MMDRZA.CoM]------------------------------')
        if str(bal) != ifbtc:
            s += 1
            print(
                Fore.GREEN,
                'Scan No:',
                Fore.WHITE,
                z,
                Fore.YELLOW,
                ' Win No:',
                Fore.WHITE,
                w,
                Fore.GREEN,
                ' Address:',
                Fore.YELLOW,
                address,
            )
            print(
                Fore.GREEN,
                'PrivateKey:',
                Fore.MAGENTA,
                private_key,
                Fore.BLUE,
                '              BAL:',
                Fore.WHITE,
                bal,
            )
            print('--------------------------------[MMDRZA.CoM]------------------------------')
            with open('BrainWalletXWalletWinnerNow.txt' , 'a') as f:
                f.write('\nADDRESS =' + str(address) + '   BAL= ' + str(bal))
                f.write('\nPRiVATEKEY =' + str(private_key))
                f.write('\nPasspharse = ' + str(passphrase))
                f.write('----------------------------------[ MMDRZA.CoM ]---------------------------------')
