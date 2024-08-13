#! /usr/bin/env nix-shell
#! nix-shell -i python3 --packages python3 python3Packages.cryptography python3Packages.pysqlcipher3

# Sources:
# https://www.enpass.io/docs/security-whitepaper-enpass/vault.html
# https://discussion.enpass.io/index.php?/topic/4446-enpass-6-encryption-details/
# https://www.zetetic.net/sqlcipher/sqlcipher-api/
# https://cryptography.io/en/latest/hazmat/primitives/aead.html
# https://github.com/hazcod/enpass-cli/issues/16#issuecomment-735114305

from binascii import unhexlify, hexlify
from getpass import getpass
from hashlib import pbkdf2_hmac, sha1
from pysqlcipher3 import dbapi2 as sqlite
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# settings for this enpass vault
enpass_db_file = "vault.enpassdb"
enpass_key_file = "keyfile.enpasskey"
pbkdf2_iters = 320_000

# Get the enpass password from the user
enpass_password = getpass("enter enpass password: ").encode('utf-8')

# The enpass master key is the concatenation of the password with the key file
# The key inside the file is 64 characters long and starts after the <key> prefix
enpass_key = open(enpass_key_file, "r").readline()[5:64+5]

# The master key is the concatenation of password with key file contents
enpass_master_key = enpass_password + unhexlify(enpass_key)

# The first 16 bytes of the database file are used as salt
enpass_db_salt = open(enpass_db_file, "rb").read(16)

# The database key is derived from the master password
# and the database salt with 320k iterations of PBKDF2-HMAC-SHA512
enpass_db_key = pbkdf2_hmac('sha512', enpass_master_key, enpass_db_salt, pbkdf2_iters, 64)

enpass_db_hex_key = enpass_db_key.hex()[:64]
print(f"enpass db key to use with sqlcipher: {enpass_db_hex_key}")

# Open DB with hex key and sqlcipher v3 compatibility mode
conn = sqlite.connect(enpass_db_file)
c = conn.cursor()
c.row_factory = sqlite.Row
c.execute("PRAGMA key=\"x'" + enpass_db_hex_key + "'\";")
c.execute("PRAGMA cipher_compatibility = 3;")
c.execute("PRAGMA cipher_page_size = 1024;")

# Loop over joined item and itemfield rows
c.execute(
        "SELECT item.uuid, item.title, item.key, item.deleted as del1, item.trashed, item.archived, "
        "       itemfield.label, itemfield.type, itemfield.value, itemfield.hash, itemfield.deleted as del2 "
        "FROM item, itemfield "
        "WHERE item.uuid = itemfield.item_uuid;"
)
print("[")
for row in c:
    # Do not proceed if the entry has been marked as deleted
    if row["del1"] + row["del2"] > 0:
        continue

    # Process password fields specifically as their value is encrypted with AES
    if row["type"] == "password" and len(row["value"]) > 0:
        # The binary item.key field contains the AES key (32 bytes)
        # concatenated with a nonce (12 bytes) for AESGCM.
        key = row["key"][:32]
        nonce = row["key"][-12:]

        # The hex itemfield.value field contains the ciphertext
        # concatenated with a tag (16 bytes = 32 hex) for authentication.
        ciphertext = bytes.fromhex(row["value"][:-32])
        tag = bytes.fromhex(row["value"][-32:])

        # The UUID without dashes is used as additional authenticated data (AAD).
        aad = bytes.fromhex(row["uuid"].replace("-", ""))

        # Decrypt the AES Galois/counter mode authenticated encryption with associated data (AEAD).
        aesgcm = AESGCM(key)
        password = aesgcm.decrypt(nonce=nonce, data=ciphertext + tag, associated_data=aad)
        print("{{ title: '{}', label: '{}', type: '{}', value: '{}', trashed: {}, archived: {} }},"
              .format(row["title"], row["label"], row["type"], password.decode("utf-8"),
                      'false' if row["trashed"] == 0 else 'true',
                      'false' if row["archived"] == 0 else 'true'))

        # Compare with the unsalted SHA1 hash of the password stored in the itemfield.hash field.
        password_hash = sha1(password).hexdigest()
        if password_hash != row["hash"]:
            print("Hash mismatch:" + password_hash + " VS " + row["hash"])

    # For any other entry having a value we can display the contents without further processing
    elif len(row["value"]) > 0:
        print("{{ title: '{}', label: '{}', type: '{}', value: '{}', trashed: {}, archived: {} }},"
              .format(row["title"], row["label"], row["type"], row["value"],
                      'false' if row["trashed"] == 0 else 'true',
                      'false' if row["archived"] == 0 else 'true'))

print("]")
c.close()
