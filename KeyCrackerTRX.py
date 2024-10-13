import hashlib
import ecdsa
import requests
import base58
from rich import print
import os

def sha256(data):
   
    return hashlib.sha256(data).digest()

def get_signing_key(raw_priv):
   return ecdsa.SigningKey.from_string(raw_priv, curve=ecdsa.SECP256k1)
def verifying_key_to_addr(key):
     pub_key = key.to_string()
    primitive_addr = b'\x41' + sha256(pub_key)[-20:]
    addr = base58.b58encode_check(primitive_addr)
    return addr
def get_tron_balance(address):
   try:
        block = requests.get(f"https://apilist.tronscan.org/api/account?address={address}")
        res = block.json()
        balance = float(res["balances"][0]["amount"])
        return balance
    except Exception as e:
        print(f"Error fetching balance for address {address}: {e}")
        return 0
def main():
    z = 0
    w = 0
    print("Starting attack, please wait...")

    while True:
        
        raw_priv = os.urandom(32)
        key = get_signing_key(raw_priv)
        address = verifying_key_to_addr(key.get_verifying_key()).decode()
        priv_hex = raw_priv.hex()

       balance = get_tron_balance(address)

        if balance > 0:
            w += 1
            with open("TRX.txt", "a") as f:
                f.write(f"\nADDRESS: {address}   Balance: {balance}")
                f.write(f"\nPRIVATE KEY: {priv_hex}")
                f.write("\n------------------------")
        else:
            print(f"[red1]Total Scan : [/][b blue]{z}[/]")
            print(f"[gold1]Address: [/]{address}    Balance: {balance}")
            print(f"[gold1]Address (hex): [/]{base58.b58decode_check(address.encode()).hex()}")
            print(f"[gold1]Private Key: [/][red1]{priv_hex}[/]")
            z += 1

if __name__ == "__main__":
    main()
