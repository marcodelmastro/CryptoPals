# [CryptoPals](https://cryptopals.com) challenge solutions

### [Challenge Set 1](https://cryptopals.com/sets/1)

* [ChallengeSet1.ipynb](ChallengeSet1.ipynb) (challenges 1 to 8)

### [Challenge Set 2](https://cryptopals.com/sets/2)

* [ChallengeSet2.ipynb](ChallengeSet2.ipynb) (challenges 9 to 16)

### [Challenge Set 3](https://cryptopals.com/sets/3)

* [ChallengeSet3.ipynb](ChallengeSet3.ipynb) (challenges 17 to 24)
    * 17: CBC padding oracle
    * 18, 19, 20: Breaking fixed-nonce CTR
    * 21, 22, 23, 24:
        * MT19937 Mersenne Twister RNG implementation
        * Time-based seed guessing
        * MT19937 cloning by inverting tempering function
        * MT19937 stream cipher, brute force and frequency analysis cracking
     
### [Challenge Set 4](https://cryptopals.com/sets/4)

* [ChallengeSet4.ipynb](ChallengeSet3.ipynb)
    * 25: Break "random access read/write" AES CTR
    * 26: CTR bitflipping. Same attack than challenge 16
    * 27: Recover the key from CBC with IV=Key. Care needed with padding errors from attack ciphertext, solved by concatenating legitmate ciphertect tail from first encryption.
    * 28, 29: SHA-1 keyed MAC length extension attack
    * 30: MD4 keyed MAC length extension attack
    * 31, 32: HMAC-SHA1 with timing leak