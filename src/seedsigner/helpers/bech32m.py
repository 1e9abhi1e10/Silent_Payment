"""
Bech32m implementation for Silent Payments.
Based on BIP-0350 and BIP-0352.
"""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 0x2bc830a3
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def encode(hrp, witver, witprog):
    """Encode a Silent Payment address."""
    ret = []
    ret.append(witver)
    ret.extend(witprog)
    checksum = bech32_create_checksum(hrp, ret)
    data = [CHARSET[d] for d in (ret + checksum)]
    return hrp + "1" + ''.join(data)

def encode_silent_payment_address(scanning_pubkey, signing_pubkey, network="main"):
    """
    Encode a Silent Payment address from scanning and signing public keys.
    
    Args:
        scanning_pubkey: The scanning public key bytes
        signing_pubkey: The signing public key bytes
        network: The network to use (main/test/regtest)
        
    Returns:
        str: The Silent Payment address
    """
    # Combine the public keys
    data = scanning_pubkey + signing_pubkey
    
    # Convert to 5-bit integers
    converted = convertbits(data, 8, 5, pad=True)
    if converted is None:
        return None
    
    # Encode with bech32m
    prefix = "sp" if network == "main" else "tsp"
    return encode(prefix, 0, converted) 