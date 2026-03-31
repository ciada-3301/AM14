from AM14 import encrypt, decrypt

# Message to encrypt (must be bytes)
message = b"Hello"

# Your shared key/password
password = "csdvbfhlivkcnhuevrgleki bvnjomclktvj hbvenicotvlu; ehne;lklv;ekngklvlgklvngcmflksng bjlhkvlnjlbgr"

# Encrypt it
ciphertext = encrypt(message, password)

# Save or send ciphertext however you want
print("Encrypted:", ciphertext)

# Later... decrypt it
plaintext = decrypt(ciphertext, password)

print("Decrypted:", plaintext)
