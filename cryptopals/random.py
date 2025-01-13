class MT19937:

    # Coefficients for MT19937
    (w, n, m, r) = (32, 624, 397, 31)
    a = 0x9908B0DF
    (u, d) = (11, 0xFFFFFFFF)
    (s, b) = (7, 0x9D2C5680)
    (t, c) = (15, 0xEFC60000)
    l = 18
    f = 1812433253

    UMASK = 0xFFFFFFFF & (0xFFFFFFFF << r)       # Limit to 32 bits
    LMASK = 0xFFFFFFFF & (0xFFFFFFFF >> (w - r)) # Limit to 32 bits

    def __init__(self, seed: int = 19650218):
        self.state_array = [0] * self.n  # Array for the state vector
        self.state_index = 0            # Index into state vector array, 0 <= state_index <= n-1
        self.initialize_state(seed)
        self.seed = seed

    def initialize_state(self, seed: int = 19650218):
        self.state_array[0] = seed & 0xFFFFFFFF  # Limit to 32 bits
        for i in range(1, self.n):
            seed = (self.f * (seed ^ (seed >> (self.w - 2))) + i) & 0xFFFFFFFF # Limit to 32 bits
            self.state_array[i] = seed
        self.state_index = 0

    def random(self):
        k = self.state_index               # Current state location
        j = (k - (self.n - 1)) % self.n    # n-1 iterations before

        x = (self.state_array[k] & self.UMASK) | (self.state_array[j] & self.LMASK)
        xA = x >> 1
        if x & 0x00000001:
            xA ^= self.a

        j = (k - (self.n - self.m)) % self.n  # n-m iterations before
        x = self.state_array[j] ^ xA          # Compute next value in the state

        self.state_array[k] = x & 0xFFFFFFFF  # Limit to 32 bits
        k = (k + 1) % self.n                  # Circular indexing
        self.state_index = k

        # Tempering
        y = x ^ (x >> self.u)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        z = y ^ (y >> self.l)
        return z & 0xFFFFFFFF  # Return 32-bit integer