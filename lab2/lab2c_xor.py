# Instead of writing it ourselves, let's use a pre-written one from PyCrypto
# PyCrypto is the library we'll be using for the project

# To start with, let's import the XOR cipher
from Crypto.Util.strxor import strxor
# We'll also use their random to get random bits for our key
from Crypto.Random import get_random_bytes

m = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness, it was the spring of hope, it was the winter of despair, we had everything before us, we had nothing before us, we were all going direct to Heaven, we were all going direct the other way - in short, the period was so far like the present period, that some of its noisiest authorities insisted on its being received, for good or for evil, in the superlative degree of comparison only. ".encode(
    "ascii")
key = get_random_bytes(16)

print(m)

# Create a new cipher object and pass in the key to be used
# For PyCrypto, the key must be between 1 and 32 bytes -- likely to discourage real world usage
cipher = strxor.new(key)
c = cipher.encrypt(m)
print(c)

# We need to reset the cipher as, by default, the cipher would continue from where it left off
# (i.e. it assumes you're going to continue encrypting or decrypting)
cipher = strxor.new(key)
m_dash = cipher.decrypt(c)
print(m_dash)
