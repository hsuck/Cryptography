import base64
import time
from functools import reduce
from random import choice
from string import printable
import binascii

from Crypto.Cipher import AES
from Crypto.Util import Counter

def ctr_encrypt( plaintext, key ):
    blockSize = len( key )
    # PKCS#5 and PKCS#7
    padding = ( blockSize - len( plaintext ) % blockSize ) or blockSize

    # iv = reduce( lambda x, y: x + choice( printable ), range(16), "" )
    iv = b'Y.q]j@#=#k(<=J*4'
    ctr = Counter.new( 128, initial_value = int( binascii.hexlify( iv ), 16 ) )
    mode = AES.new( key, AES.MODE_CTR, counter = ctr )
    # print( "plaintext:", plaintext + padding * bytes([padding]) )
    ciphertext = mode.encrypt( ( plaintext + padding * bytes([padding]) ) )
    # print( "ciphertext:", ciphertext )

    return base64.b64encode( iv + ciphertext )

def ctr_decrypt( ciphertext, key ):
    ciphertext = base64.b64decode( ciphertext )
    ctr = Counter.new( 128, initial_value = int( binascii.hexlify( ciphertext[:AES.block_size] ), 16 ) )
    mode = AES.new( key, AES.MODE_CTR, counter = ctr )
    plaintext = mode.decrypt( ciphertext[AES.block_size:] )
    return plaintext[:-ord( chr( plaintext[-1] ) )]


if __name__ == '__main__':
    # key = reduce( lambda x, y: x + choice( printable ), range(16), "" )
    key = b'HV*_YsZ,7CIWjF|J' # 16位 AES-128
    # print( "key:", key.encode() )

    with open( "./test.bin", "rb" ) as f:
        content = f.read()
    print( "File size is:", len( content ), "bytes" )

    start = time.time()
    ciphertext = ctr_encrypt( content, key )
    end = time.time()
    print("The time used to encrypt this is given below")
    print( round( end - start, 5 ), "secs" )
    print( "Rate:", round( len( content ) / ( end - start ), 5 ), "bytes/sec" )

    with open( "./test-CTR.bin.enc", "wb"  ) as f:
        f.write( ciphertext )

    plaintext = ctr_decrypt( ciphertext, key )
    # print( "plaintext:", plaintext )
    with open( "./test-CTR.bin.dec", "wb"  ) as f:
        f.write( plaintext )
