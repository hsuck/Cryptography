import base64
import binascii
import json
import time
from functools import reduce
from random import choice
from string import printable

from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Util import Counter

def chacha20_encrypt( plaintext, key ):
    mode = ChaCha20.new( key = key )
    ciphertext = mode.encrypt( plaintext )
    # print( "ciphertext:", ciphertext )

    nonce = base64.b64encode( mode.nonce ).decode('utf-8')
    ct = base64.b64encode( ciphertext ).decode('utf-8')

    return json.dumps( { 'nonce': nonce, 'ciphertext': ct } )

def chacha20_decrypt( ciphertext, key ):
    b64 = json.loads( ciphertext )
    nonce = base64.b64decode( b64['nonce'] )
    ciphertext = base64.b64decode( b64['ciphertext'] )
    mode = ChaCha20.new( key = key, nonce = nonce )
    plaintext = mode.decrypt( ciphertext )
    return plaintext


if __name__ == '__main__':
    # key = reduce( lambda x, y: x + choice( printable ), range(32), "" )
    key = b"hwWe\mS2`kvu8,z/|hvop7^~)ZUgQhHT" # 32位
    # print( "key:", key.encode() )

    with open( "./test.bin", "rb" ) as f:
        content = f.read()
    print( "File size is:", len( content ), "bytes" )

    start = time.time()
    ciphertext = chacha20_encrypt( content, key )
    end = time.time()
    print("The time used to encrypt this is given below")
    print( round( end - start, 5 ), "secs" )
    print( "Rate:", round( len( content ) / ( end - start ), 5 ), "bytes/sec" )

    # print( "ciphertext:", ciphertext )
    with open( "./test-ChaCha20.bin.enc", "w"  ) as f:
        f.write( ciphertext )

    plaintext = chacha20_decrypt( ciphertext, key )
    # print( "plaintext:", plaintext )
    with open( "./test-ChaCha20.bin.dec", "wb"  ) as f:
        f.write( plaintext )
