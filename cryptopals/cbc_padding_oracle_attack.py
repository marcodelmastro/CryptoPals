from .utils import bytes_xor
from Cryptodome.Cipher import AES

def single_block_attack(block, oracle, BLOCKSIZE=AES.block_size):
    zeroing_iv = [0]*BLOCKSIZE # zeroing IV starts out nulled
    for pad_value in range(1,BLOCKSIZE+1): # explore all possible padding values to fill all zeroing block
        padding_iv = [pad_value^b for b in zeroing_iv] # xor pad_value with ziv before searching next ziv byte
        for iv_candidate in range(256): # all possible values for IV byte
            padding_iv[-pad_value] = iv_candidate
            iv = bytes(padding_iv)
            if oracle(block, iv): # padding is valid
                # in case pad_value==1, make sure the padding really is of length 1 
                # by changing penultimate block and querying the oracle again
                if pad_value == 1: 
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(block, iv):
                        continue  # false positive, keep searching with next pad_value
                break # good pad_value found
        zeroing_iv[-pad_value] = iv_candidate ^ pad_value
    return bytes(zeroing_iv)

def full_attack(iv, cipher, oracle, BLOCKSIZE=AES.block_size):
    message = iv + cipher
    blocks = [message[i:i+BLOCKSIZE] for i in range(0, len(message), BLOCKSIZE)]
    result = b''
    iv = blocks[0]
    for cipher in blocks[1:]:
        deckey = single_block_attack(cipher,oracle)
        plaintext = bytes_xor(deckey,iv)
        result += plaintext
        iv = cipher
    return result