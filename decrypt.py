import base64
import sys
import os
import subprocess
import binascii
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SEVTOOL = "Path to the sevtool binary that exports the KDF"

def swap_bytes(data):
    data_int = int.from_bytes(data, 'little')
    return (data_int).to_bytes(len(data), 'big')

def build_ecdsa_pubkey(qx_bytes, qy_bytes):
    """Build ecdsa public key from provided curve point. Returns an
    EllipticCurvePublicKey object. Point must be specified by qx and qy
    values in little-endian byte order. Curve defaults to NIST-P384.
    See: AMD SEV API ver. 0.22 Chapter 4.5 and Appendix C.2"""

    pubkey_qx = int.from_bytes(qx_bytes, 'little')
    pubkey_qy = int.from_bytes(qy_bytes, 'little')

    curve = ec.SECP384R1()  # NIST-P384
    pub_numbers = ec.EllipticCurvePublicNumbers(pubkey_qx, pubkey_qy, curve)

    ec_pubkey = pub_numbers.public_key(default_backend())

    return ec_pubkey

def derive_secret(secret,context,nonce):
    """Call the sevtool key key derivation function.
    Returns the derived key."""
    # TODO: Implement in python
    if nonce is not None:
        out = subprocess.Popen([SEVTOOL,"--kdf",binascii.hexlify(secret),context,binascii.hexlify(nonce)],stdout=subprocess.PIPE)
    else:
        out = subprocess.Popen([SEVTOOL,"--kdf",binascii.hexlify(secret),context],stdout=subprocess.PIPE)

    return binascii.unhexlify(out.stdout.readlines()[0].rstrip())

# Read private PDH
with open(sys.argv[1], 'rb') as f:
    pdh_priv = load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend())

# Read remote public PDH
with open(sys.argv[2],'rb') as f:
    remote_pdh = f.read()
    remote_pdh = build_ecdsa_pubkey(remote_pdh[0x14:0x14+0x48],
                                    remote_pdh[0x5c:0x5c+0x48])

# Open encrypted memory file
with open(sys.argv[3], 'rb') as f:
    # TODO don't rely on hard-coded constants

    f.seek(0x19d)
    policy = f.read(4)
    f.seek(0x1A1)
    pdh_len = f.read(4)

    # Seek to the beginning of the PDH
    f.seek(0x1A5)
    pdh_len = int.from_bytes(pdh_len,'big')
    # pdh = f.read(pdh_len)

    #Seek to the beginning of the session len
    f.seek(0x1A5 + pdh_len)
    session_len = int.from_bytes(f.read(4), 'big')

    # Read session data
    f.seek(0x1A5 + 4 + pdh_len)
    session_data = f.read(session_len)

    begin_chunk = 0x1A5 + 4 + pdh_len + session_len
    print(hex(begin_chunk))


# DH Static Unified Model - Section 2.2.2 AMD SEV API
print("Deriving shared secret")
shared_secret = pdh_priv.exchange(ec.ECDH(), remote_pdh)

# Get session data
nonce = session_data[:0x10]
wrapped_tk = session_data[0x10:0x30]
iv = session_data[0x30:0x40]
hmac_tk = session_data[0x40:0x60]
hmac_policy = session_data[0x60:0x80]

print("Deriving master secret, key-encryption-key (KEK) and key-integrity-key (KIK)")
master_secret = derive_secret(shared_secret,b'sev-master-secret',nonce)
kek = derive_secret(master_secret,b'sev-kek',None)
kik = derive_secret(master_secret,b'sev-kik',None)

calc_hmac = hmac.HMAC(kik, hashes.SHA256(), backend=default_backend())

calc_hmac.update(wrapped_tk)

# Sanity check: Verify that derived kik is correct.
try:
    calc_hmac.verify(hmac_tk)
except InvalidSignature:
    print("ERROR, couldn't verify using kik")
else:
    print("Verified wrapped_tk using kik")



aes = algorithms.AES(kek)
decryptor = Cipher(aes,modes.CTR(iv),default_backend()).decryptor()

tiktek = decryptor.update(wrapped_tk) + decryptor.finalize()

# Get TIK and TEK
tek = tiktek[:0x10]
tik = tiktek[0x10:]

calc_hmac_pol = hmac.HMAC(tik, hashes.SHA256(), backend=default_backend())
calc_hmac_pol.update(swap_bytes(policy))

# Sanity check: Verify that decrypted TIK is correct.
try:
    calc_hmac_pol.verify(hmac_policy)
except InvalidSignature:
    print("ERROR, couldn't verify policy using tik")
    sys.exit(-1)
else:
    print("Verified policy using tik")

print("Starting to decrypt...")
out = open("./out",'ab')

# Don't look at this code, please. It is hideous.
with open(sys.argv[3],'rb') as f:
    while(True):
        # Read transport hdr
        f.seek(begin_chunk)
        hdr_size = int.from_bytes(f.read(4), 'big')
        if hdr_size != 0x34:
            break
        print("HDR size: %x at offset %x" % (hdr_size, f.tell()))
        f.seek(begin_chunk + 4)
        hdr = f.read(hdr_size)

        data_flags = hdr[:4]
        data_iv = hdr[4:20]
        data_mac = hdr[0x14:0x14+0x20]
        f.seek(begin_chunk + 4 + hdr_size)
        data_size = int.from_bytes(f.read(4), 'big')
        if data_size != 0x1000:
            break
        print("Data size: %x at offset: %x" % (data_size,f.tell()))

        f.seek(begin_chunk + 4 + hdr_size + 4)
        data = f.read(data_size)
        if len(data) != data_size:
            print("Couldn't read the full data chuck. data_size: %x len(data): %x" % (data_size, len(data)))
            print(" Offset in file: %x" % f.tell())
            break
        if data_size == 0:
            print("data_size is zero")
            print(" Offset in file: %x" % f.tell())
            break

        aes = algorithms.AES(tek)
        decryptor = Cipher(aes,modes.CTR(data_iv),default_backend()).decryptor()
        pos = 0
        current_pos = f.tell()
        while True:
            f.seek(current_pos + pos)
            if f.read(8) == b'\x00\x00\x00\x34\x00\x00\x00\x00': # TODO: Don't assume a fixed header size of 0x34
                break
            pos += 1
            cur_pos = f.tell()
            f.seek(0,os.SEEK_END)
            if cur_pos >= f.tell():
                break
            f.seek(cur_pos)
        begin_chunk = current_pos + pos
        print("Begin of new chuck at %x offset: %x" % (begin_chunk, f.tell()))

        out.write(decryptor.update(data) + decryptor.finalize())


out.close()
