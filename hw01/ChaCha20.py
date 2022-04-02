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

    start = time.time()
    ciphertext = mode.encrypt( plaintext )
    end = time.time()

    print("The time used to encrypt this is given below:")
    print( round( end - start, 5 ), "secs" )
    print( "Rate:", round( len( content ) / ( end - start ), 5 ), "bytes/sec" )

    return base64.b64encode( mode.nonce + ciphertext ).decode('utf8')

def chacha20_decrypt( ciphertext, key ):
    # 密文的前 8 個位元組為 nonce
    ciphertext = base64.b64decode( ciphertext )
    mode = ChaCha20.new( key = key, nonce = ciphertext[:8] )
    plaintext = mode.decrypt( ciphertext[8:] )

    return plaintext


if __name__ == '__main__':
    # randomly generate key or use fixed one
    # key = reduce( lambda x, y: x + choice( printable ), range(32), "" )
    key = b"hwWe\mS2`kvu8,z/|hvop7^~)ZUgQhHT" # 32位

    # read file
    with open( "./test.bin", "rb" ) as f:
        content = f.read()
    print( "File size is:", len( content ), "bytes" )

    # encrypt it
    ciphertext = chacha20_encrypt( content, key )

    # write ciphertext to file
    with open( "./test-ChaCha20.bin.enc", "w"  ) as f:
        f.write( ciphertext )

    # decrypt the above ciphertext and write it to file
    plaintext = chacha20_decrypt( ciphertext, key )
    with open( "./test-ChaCha20.bin.dec", "wb"  ) as f:
        f.write( plaintext )
