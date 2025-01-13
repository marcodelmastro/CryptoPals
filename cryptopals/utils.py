from base64 import b16decode, b64encode, b64decode

def hex_to_b64(data_hex: bytes) -> bytes:
    return b64encode(b16decode(data_hex,casefold=True))

def _bytes_xor(a: bytes, b: bytes, quiet=True, check_lens=False) -> bytes:
    if not quiet:
        print(a, '\u2295', b)
    if check_lens and len(a) != len(b):
        raise ValueError("bytestring  lengths are not equal")
    return bytes(b1^b2 for b1, b2 in zip(a,b))

def bytes_xor(*args: bytes, quiet = True, check_lens=False) -> bytes:
    assert len(args) > 0
    result = args[0]
    for arg in args[1:]:
        result = _bytes_xor(result, arg, quiet=quiet, check_lens=check_lens)
    return result

from itertools import cycle

def repeating_key_xor(plaintext: bytes, key: bytes):
    return bytes(p^k for p,k in zip(plaintext,cycle(key)))

freqs_letters ={
    'a': 0.07803539798774925,
    'b': 0.013395918987177907,
    'c': 0.023684960647465267,
    'd': 0.04677742385598827,
    'e': 0.1267185226399993,
    'f': 0.020981379896661476,
    'g': 0.018664914069200216,
    'h': 0.056452807454514,
    'i': 0.06095006217488881,
    'j': 0.0008202853198801562,
    'k': 0.007660145460610745,
    'l': 0.04054873229198174,
    'm': 0.02590682604349877,
    'n': 0.06824674282001397,
    'o': 0.07664128636670861,
    'p': 0.015221956262237374,
    'q': 0.0011737921952154587,
    'r': 0.05948624497279615,
    's': 0.062279447184952555,
    't': 0.083662878915182,
    'u': 0.02979166744463074,
    'v': 0.009519790783677443,
    'w': 0.022626929506496935,
    'x': 0.0015472149508513416,
    'y': 0.02121414674767451,
    'z': 0.00040578606112432613,
    'A': 0.0014687961721678061,
    'B': 0.0008377117151431641,
    'C': 0.00043192565401883794,
    'D': 0.0005053654626272282,
    'E': 0.0006958110680015285,
    'F': 0.0005090996901835871,
    'G': 0.0006435318822125049,
    'H': 0.0013468114053267512,
    'I': 0.010201909683972322,
    'J': 0.0008177958348425836,
    'K': 2.489485037572553e-05,
    'L': 0.00048420483980786156,
    'M': 0.0022007047732141368,
    'N': 0.0006136580617616343,
    'O': 0.00046802318706363994,
    'P': 0.00043690462409398304,
    'Q': 1.9915880300580425e-05,
    'R': 0.0010144651528108154,
    'S': 0.0010430942307428997,
    'T': 0.0017575764365262223,
    'U': 9.211094639018445e-05,
    'V': 0.00011451631172833744,
    'W': 0.0010144651528108154,
    'X': 7.717403616474914e-05,
    'Y': 0.0007592929364596287,
    'Z': 4.978970075145106e-06
}

def score_text(text: bytes, freqs=freqs_letters) -> float:
    l = len(text)
    return sum([abs(text.count(ord(letter))/l - freq_exp) for letter, freq_exp in freqs.items()])

def crack_single_xor(cypher: bytes, freqs=freqs_letters) -> bytes:
    best_guess = (float('inf'), None, None) # score, plaintext guess, key guess
    best_key = ""
    for key in range(256):
        key_full = bytes([key])*len(cypher)
        plaintext = bytes_xor(cypher,key_full)
        score = score_text(plaintext, freqs=freqs_letters)
        curr_guess = (score, plaintext, bytes([key]))
        best_guess = min(best_guess, curr_guess)
    return best_guess

from itertools import cycle

def repeating_key_xor(plaintext: bytes, key: bytes):
    return bytes(p^k for p,k in zip(plaintext,cycle(key)))

def hamming_distance(s1: bytes, s2: bytes) -> int:
    return sum([bin(b1^b2).count("1") for b1,b2 in zip(s1,s2)])

from itertools import combinations

def guess_rep_key_xor(b: bytes, kmin=2, kmax=40, quiet=True):
    # guess keysize by testing testing several values and choosing that giving the smallest
    # normalised Hamming distance on blocks of that size
    keys = []
    for ks in range(kmin,kmax+1):
        # compute normalised Hamming distance between all combinations of blocks of size ks
        nbloc = len(b)//ks
        blocks = [ b[j*ks:(j+1)*ks] for j in range(nbloc) ]
        ndave = 0
        ncomb = 0
        for c in combinations(blocks,2):            
            ndave += hamming_distance(c[0],c[1])
            ncomb += 1
        ndave /= ncomb*ks
        keys.append((ks,ndave))

    # choose keysize as that giving smallest average Hamming distance between neigbouring blocks
    keys = sorted(keys,key=lambda x: x[1])
    keysize = keys[0][0]
    if not quiet:
        print("Guessed KEYSIZE =",keysize)
    
    # Break the ciphertext into blocks of KEYSIZE length, then transpose the blocks. Make a block that is the
    # first byte of every block, and a block that is the second byte of every block, and so on.
    # This is because each corresponding byte in all blocks has been encrypted with the same key character,
    # thus I can try to guess the key character it using the single-character XOR attach implemented at point 4.
    nblocks = len(b)//keysize # I'm skipping the last part of the cypher, I could maybe pad it to use the last block
    blocks = []
    for k in range(keysize):
        tblock = []
        for i in range(nblocks):
            tblock.append(b[k+keysize*i])
        blocks.append(tblock)

    # Solve each block as if it was single-character XOR, recompose the key!
    key = b""
    for block in blocks:
        best_guess = crack_single_xor(block)
        key += best_guess[2]
    if not quiet:
        print("Guessed KEY =",key)
    return key

from Cryptodome.Cipher import AES

def pkcs7_pad(b: bytes, blocksize: int = 16) -> bytes:
    if blocksize == 16:
        pad_len = blocksize - (len(b) & 15)
    else:
        pad_len = blocksize - (len(b) % blocksize)
    return b + bytes([pad_len]) * pad_len

class PaddingError(Exception):
    pass
    
def pkcs7_strip(b: bytes) -> bytes:
    n = b[-1]
    if n==0 or len(b)<n or not b.endswith(bytes([n])*n): # invalid padding
        raise PaddingError
    else:
        return b[:-n]

def aes_ecb_decrypt(cipher: bytes, key: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_ECB) 
    return aes.decrypt(cipher)

def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    keysize = len(key)
    aes_ecb = AES.new(key,AES.MODE_ECB)
    return aes_ecb.encrypt( pkcs7_pad(plaintext, len(plaintext)+keysize-len(plaintext)%keysize) )

def bytes_to_chuncks(b: bytes, chunksize=16) -> list:
    return [ b[i:i+chunksize] for i in range(0,len(b),chunksize) ]

def detect_aes_ecb_mode(cipher: bytes, blocksize=16):
    blocks = bytes_to_chuncks(cipher,blocksize)
    return (len(blocks) - len(set(blocks))) != 0

def aes_cbc_decrypt(cipher: bytes, key: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    bsize = len(key)
    blocks = bytes_to_chuncks(cipher,bsize)
    IV = bsize*b"\x00"    
    plaintext = b""
    for i in range(len(blocks)):
        # decrypt block with AES ECB mode
        plainblock = aes.decrypt(blocks[i])
        # XOR with IV or previous cipher block
        plainblock = bytes_xor(plainblock,IV) if i==0 else bytes_xor(plainblock,blocks[i-1])
        plaintext += plainblock
    return plaintext

import os

def generate_aes_key(keylen=16):
    return os.urandom(keylen)

import math

def generate_ctr_keystream(key: bytes, nonce: int, msglen: int) -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    keystream = b""
    for counter in range(math.ceil(msglen/AES.block_size)): # generate for N blocks covering all message 
        to_be_encrypted = nonce.to_bytes(length=AES.block_size//2, byteorder='little') + counter.to_bytes(length=AES.block_size//2, byteorder='little')
        keystream += aes.encrypt(to_be_encrypted)
    return keystream[:msglen] # trim keystream to message lenght (if shorter than N blocks 

def aes_ctr_decode_encode(b: bytes, key: bytes, nonce: int) -> bytes:
    return bytes_xor(b,generate_ctr_keystream(key,nonce,len(b)))
