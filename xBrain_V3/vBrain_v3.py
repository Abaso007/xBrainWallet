import codecs , random , hashlib , ecdsa , sys , time
from time import sleep
from rich.console import Console
from rich import print
from rich.panel import Panel
from rich.console import Console
from lxml import html
import requests
import threading

console = Console()
console.clear()

filexname = input('INSERT HERE File Name <---------|Without type file .txt|----------> : ')
#
def Bal(address):
    urlblock = f"https://bitcoin.atomicwallet.io/address/{address}"
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
    treetxid = source_code.xpath(xpatch_txid)
    return str(treetxid[0].text_content())


def xBal(address):
    urlblock = f"https://bitcoin.atomicwallet.io/address/{address}"
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    treetxid = source_code.xpath(xpatch_txid)
    return str(treetxid[0].text_content())


mylist = []

filename = str(f"{filexname}.txt")
with open(filename, newline = '' , encoding = 'utf-8') as f:
    mylist.extend(line.strip() for line in f)


class BrainWallet :

    @staticmethod
    def generate_address_from_passphrase(passphrase):
        private_key = hashlib.sha256(passphrase.encode('utf-8')).hexdigest()
        address = BrainWallet.generate_address_from_private_key(private_key)
        return private_key , address

    @staticmethod
    def generate_address_from_private_key(private_key):
        public_key = BrainWallet.__private_to_public(private_key)
        return BrainWallet.__public_to_address(public_key)

    @staticmethod
    def __private_to_public(private_key):
        private_key_bytes = codecs.decode(private_key , 'hex')
        key = ecdsa.SigningKey.from_string(
            private_key_bytes , curve = ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes , 'hex')
        bitcoin_byte = b'04'
        return bitcoin_byte+key_hex

    @staticmethod
    def __public_to_address(public_key):
        public_key_bytes = codecs.decode(public_key , 'hex')
        # Run SHA256 for the public key
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest , 'hex')
        network_byte = b'00'
        network_bitcoin_public_key = network_byte+ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key , 'hex')
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest , 'hex')
        checksum = sha256_2_hex[:8]
        address_hex = (network_bitcoin_public_key+checksum).decode('utf-8')
        return BrainWallet.base58(address_hex)

    @staticmethod
    def base58(address_hex):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        leading_zeros = len(address_hex)-len(address_hex.lstrip('0'))
        address_int = int(address_hex , 16)
        while address_int > 0 :
            digit = address_int%58
            digit_char = alphabet[digit]
            b58_string = digit_char+b58_string
            address_int //= 58
        ones = leading_zeros//2
        for _ in range(ones):
            b58_string = f'1{b58_string}'
        return b58_string


def MmDrza():
    s = 0
    w = 0
    count = 0
    xpatch_txid = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
    ifbtc = '0 BTC'
    for i in range(len(mylist)):
        count += 2
        passphrase = mylist[i]
        wallet = BrainWallet()
        private_key , address = wallet.generate_address_from_passphrase(passphrase)
        dec = int(private_key , 16)
        urlblock = f"https://bitcoin.atomicwallet.io/address/{address}"
        respone_block = requests.get(urlblock)
        byte_string = respone_block.content
        source_code = html.fromstring(byte_string)
        treetxid = source_code.xpath(xpatch_txid)
        xVol = str(treetxid[0].text_content())
        bal = xVol
        if int(bal) > 0:
            urlblock1 = f"https://bitcoin.atomicwallet.io/address/{address}"
            respone_block1 = requests.get(urlblock1)
            byte_string1 = respone_block1.content
            source_code1 = html.fromstring(byte_string1)
            xpatch_txid1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            treetxid1 = source_code1.xpath(xpatch_txid1)
            xVol1 = str(treetxid1[0].text_content())
            val = xVol1
            MmdrzaPanel = str(
                (
                    (
                        (
                            (
                                (
                                    (
                                        (
                                            (
                                                (
                                                    '[gold1 on grey15]Total Checked: '
                                                    + '[orange_red1]'
                                                    + str(count)
                                                    + '[/][gold1 on grey15] '
                                                    + ' Win:'
                                                    + '[white]'
                                                    + str(w)
                                                    + '[/]'
                                                    + '[/][gold1]                  TX: '
                                                    + '[/][aquamarine1]'
                                                    + bal
                                                )
                                                + '[gold1]  BAL:[aquamarine1]'
                                            )
                                            + val
                                        )
                                        + '\n[/][gold1 on grey15]Addr: '
                                    )
                                    + '[white] '
                                )
                                + str(address)
                                + '[gold1 on grey15]                  Passphrase: '
                            )
                            + '[orange_red1]'
                        )
                        + str(passphrase)
                        + '[/]\nPRIVATEKEY: [grey54]'
                    )
                    + str(private_key)
                    + '[/]'
                )
            )
            style = "gold1 on grey11"
            with open(f"vBrain_{str(filexname)}_TX.txt", "a") as f1:
                f1.write('\nBitcoin Address Compressed : '+address+'  TX = ' + bal)
                f1.write('\nPassphrase       : '+passphrase)
                f1.write('\nPrivate Key      : '+private_key)
                f1.write('\nBalance: ' + val)
                f1.write('\n-------------- Programmer Mmdrza.Com ----------------------\n')
            console.print(
                Panel(
                    MmdrzaPanel,
                    title="[white]Win Wallet [/]",
                    subtitle="[green_yellow blink] Mmdrza.Com [/]",
                    style="red",
                ),
                style=style,
                justify="full",
            )

            w += 1
            if val != ifbtc:
                s += 1
                MmdrzaB = str(
                    (
                        (
                            (
                                (
                                    (
                                        (
                                            (
                                                '[green on grey15]Total Checked: '
                                                + '[orange_red1]'
                                                + str(count)
                                                + '[/][gold1 on grey15] '
                                                + ' Win:'
                                                + '[white]'
                                                + str(w)
                                                + '[/]'
                                                + '[/][gold1]                  TX: '
                                                + '[/][aquamarine1]'
                                                + bal
                                            )
                                            + '[gold1]  BAL:[aquamarine1]'
                                        )
                                        + val
                                    )
                                    + '\n[/][gold1 on grey15]Addr: '
                                )
                                + '[white] '
                            )
                            + str(address)
                            + '[/]\nPRIVATEKEY: [grey54]'
                        )
                        + str(private_key)
                        + '[/]'
                    )
                )
                console.print(
                    Panel(
                        MmdrzaB,
                        title="[white]Win Wallet [/]",
                        subtitle="[green_yellow blink] Mmdrza.Com [/]",
                        style="green",
                    ),
                    style=style,
                    justify="full",
                )

                with open(f"vBrain_{str(filexname)}_Balance.txt", "a") as f:
                    f.write('\nBitcoin Address Compressed : '+address+'  TX = ' + bal)
                    f.write('\nPassphrase       : '+passphrase)
                    f.write('\nPrivate Key      : '+private_key)
                    f.write('\nBalance: ' + val)
                    f.write('\n-------------- Programmer Mmdrza.Com ----------------------\n')
        else:
            console.print(
                f'[gold1 on grey7]Scan:[light_goldenred1]{count}[gold1] Tx:[white]{str(w)}[green] Rich:[white]{str(s)}[/][yellow] Add:[green1]{str(address)}[red1]  TXID:[white]{bal}[gold1]  Passphars:[white]{str(passphrase)}'
            )


thr = threading.Thread(target = MmDrza , args = ())
thr.start()
thr.join()
