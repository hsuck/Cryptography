import base64
import time
from functools import reduce
from random import choice
from string import printable
import binascii

from Crypto.Cipher import AES
from Crypto.Util import Counter

def ctr_encrypt( plaintext, key ):
    # randomly generate iv or use fixed one
    # iv = reduce( lambda x, y: x + choice( printable ), range(16), "" )
    iv = b'Y.q]j@#=#k(<=J*4'

    # create a counter with initial value iv
    ctr = Counter.new( 128, initial_value = int( binascii.hexlify( iv ), 16 ) )
    mode = AES.new( key, AES.MODE_CTR, counter = ctr )

    start = time.time()
    ciphertext = mode.encrypt( plaintext )
    end = time.time()

    print("The time used to encrypt this is given below")
    print( round( end - start, 5 ), "secs" )
    print( "Rate:", round( len( content ) / ( end - start ), 5 ), "bytes/sec" )

    return base64.b64encode( iv + ciphertext ).decode('utf8')

def ctr_decrypt( ciphertext, key ):
    # 密文的前 16 個位元組為 iv
    ciphertext = base64.b64decode( ciphertext )

    # create the same counter with initial value iv
    ctr = Counter.new( 128, initial_value = int( binascii.hexlify( ciphertext[:AES.block_size] ), 16 ) )
    mode = AES.new( key, AES.MODE_CTR, counter = ctr )

    plaintext = mode.decrypt( ciphertext[AES.block_size:] )

    return plaintext

if __name__ == '__main__':
    # randomly generate key or use fixed one
    # key = reduce( lambda x, y: x + choice( printable ), range(16), "" )
    key = b'HV*_YsZ,7CIWjF|J' # 16位 AES-128

    # read file
    with open( "./test.bin", "rb" ) as f:
        content = f.read()
    print( "File size is:", len( content ), "bytes" )

    # encrypt it
    ciphertext = ctr_encrypt( content, key )

    # write ciphertext to file
    with open( "./test-CTR.bin.enc", "w"  ) as f:
        f.write( ciphertext )

    # decrypt the above ciphertext and write it to file
    plaintext = ctr_decrypt( ciphertext, key )
    with open( "./test-CTR.bin.dec", "wb"  ) as f:
        f.write( plaintext )
