import base64
import time
from functools import reduce
from random import choice
from string import printable

from Crypto.Cipher import AES


def cbc_encrypt( plaintext, key ):
    """
    AES-CBC 加密
    key 必須是 16(AES-128)、24(AES-192) 或 32(AES-256) 位元組的 AES 金鑰；
    初始化向量 iv 為隨機的 16 位字串 (必須是16位)，
    解密需要用到這個相同的 iv，因此將它包含在密文的開頭。
    """
    blockSize = len( key )
    # PKCS#5 and PKCS#7
    padding = ( blockSize - len( plaintext ) % blockSize ) or blockSize

    # randomly generate iv or use fixed one
    # iv = reduce( lambda x, y: x + choice( printable ), range(16), "" )
    iv = b'Y.q]j@#=#k(<=J*4'

    mode = AES.new( key, AES.MODE_CBC, iv )

    # pad to multiples of 16
    start = time.time()
    ciphertext = mode.encrypt( ( plaintext + padding * bytes([padding]) ) )
    end = time.time()

    print("The time used to encrypt this is given below:")
    print( round( end - start, 5 ), "secs" )
    print( "Rate:", round( len( content ) / ( end - start ), 5 ), "bytes/sec" )

    return base64.b64encode( iv + ciphertext ).decode('utf8')

def cbc_decrypt( ciphertext, key ):
    """
    AES-CBC 解密
    密文的前 16 個位元組為 iv
    """
    ciphertext = base64.b64decode( ciphertext )
    mode = AES.new( key, AES.MODE_CBC, ciphertext[:AES.block_size] )
    plaintext = mode.decrypt( ciphertext[AES.block_size:] )
    # remove padding and return
    return plaintext[:-ord( chr( plaintext[-1] ) )]

if __name__ == '__main__':
    # randomly generate key or use fixed one
    # key = reduce( lambda x, y: x + choice( printable ), range(32), "" )
    key = b"hwWe\mS2`kvu8,z/|hvop7^~)ZUgQhHT" # 32位 AES-256

    # read file
    with open( "./test.bin", "rb" ) as f:
        content = f.read()
    print( "File size is:", len( content ), "bytes" )

    # encrypt it
    ciphertext = cbc_encrypt( content, key )

    # write ciphertext to file
    with open( "./test-CBC.bin.enc", "w"  ) as f:
        f.write( ciphertext )

    # decrypt the above ciphertext and write it to file
    plaintext = cbc_decrypt( ciphertext, key )
    with open( "./test-CBC.bin.dec", "wb"  ) as f:
        f.write( plaintext )
