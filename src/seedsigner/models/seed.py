import logging
import unicodedata
import hashlib
import hmac

from binascii import hexlify
from embit import bip39, bip32, bip85
from embit.networks import NETWORKS
from typing import List

from seedsigner.models.settings import SettingsConstants

logger = logging.getLogger(__name__)


class InvalidSeedException(Exception):
    pass



class Seed:
    def __init__(self,
                 mnemonic: List[str] = None,
                 passphrase: str = "",
                 wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH) -> None:
        self._wordlist_language_code = wordlist_language_code

        if not mnemonic:
            raise Exception("Must initialize a Seed with a mnemonic List[str]")
        self._mnemonic: List[str] = unicodedata.normalize("NFKD", " ".join(mnemonic).strip()).split()

        self._passphrase: str = ""
        self.set_passphrase(passphrase, regenerate_seed=False)

        self.seed_bytes: bytes = None
        self._generate_seed()


    @staticmethod
    def get_wordlist(wordlist_language_code: str = SettingsConstants.WORDLIST_LANGUAGE__ENGLISH) -> List[str]:
        # TODO: Support other BIP-39 wordlist languages!
        if wordlist_language_code == SettingsConstants.WORDLIST_LANGUAGE__ENGLISH:
            return bip39.WORDLIST
        else:
            raise Exception(f"Unrecognized wordlist_language_code {wordlist_language_code}")


    def _generate_seed(self):
        try:
            self.seed_bytes = bip39.mnemonic_to_seed(self.mnemonic_str, password=self._passphrase, wordlist=self.wordlist)
        except Exception as e:
            logger.info(repr(e), exc_info=True)
            raise InvalidSeedException(repr(e))


    @property
    def mnemonic_str(self) -> str:
        return " ".join(self._mnemonic)
    

    @property
    def mnemonic_list(self) -> List[str]:
        return self._mnemonic


    @property 
    def wordlist_language_code(self) -> str:
        return self._wordlist_language_code


    @property
    def mnemonic_display_str(self) -> str:
        return unicodedata.normalize("NFC", " ".join(self._mnemonic))
    

    @property
    def mnemonic_display_list(self) -> List[str]:
        return unicodedata.normalize("NFC", " ".join(self._mnemonic)).split()


    @property
    def has_passphrase(self):
        return self._passphrase != ""


    @property
    def passphrase(self):
        return self._passphrase
        

    @property
    def passphrase_display(self):
        return unicodedata.normalize("NFC", self._passphrase)


    def set_passphrase(self, passphrase: str, regenerate_seed: bool = True):
        if passphrase:
            self._passphrase = unicodedata.normalize("NFKD", passphrase)
        else:
            # Passphrase must always have a string value, even if it's just the empty
            # string.
            self._passphrase = ""

        if regenerate_seed:
            # Regenerate the internal seed since passphrase changes the result
            self._generate_seed()


    @property
    def wordlist(self) -> List[str]:
        return Seed.get_wordlist(self.wordlist_language_code)


    def set_wordlist_language_code(self, language_code: str):
        # TODO: Support other BIP-39 wordlist languages!
        raise Exception("Not yet implemented!")


    @property
    def script_override(self) -> str:
        return None


    def derivation_override(self, sig_type: str = SettingsConstants.SINGLE_SIG) -> str:
        return None


    def detect_version(self, derivation_path: str, network: str = SettingsConstants.MAINNET, sig_type: str = SettingsConstants.SINGLE_SIG) -> str:
        embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]
        return bip32.detect_version(derivation_path, default="xpub", network=embit_network)


    @property
    def passphrase_label(self) -> str:
        return SettingsConstants.LABEL__BIP39_PASSPHRASE


    @property
    def seedqr_supported(self) -> bool:
        return True


    @property
    def bip85_supported(self) -> bool:
        return True


    def get_fingerprint(self, network: str = SettingsConstants.MAINNET) -> str:
        root = bip32.HDKey.from_seed(self.seed_bytes, version=NETWORKS[SettingsConstants.map_network_to_embit(network)]["xprv"])
        return hexlify(root.child(0).fingerprint).decode('utf-8')


    def get_xpub(self, wallet_path: str = '/', network: str = SettingsConstants.MAINNET):
        # Import here to avoid slow startup times; takes 1.35s to import the first time
        from seedsigner.helpers import embit_utils
        return embit_utils.get_xpub(seed_bytes=self.seed_bytes, derivation_path=wallet_path, embit_network=SettingsConstants.map_network_to_embit(network))


    def get_bip85_child_mnemonic(self, bip85_index: int, bip85_num_words: int, network: str = SettingsConstants.MAINNET):
        """Derives the seed's nth BIP-85 child mnemonic"""
        root = bip32.HDKey.from_seed(self.seed_bytes, version=NETWORKS[SettingsConstants.map_network_to_embit(network)]["xprv"])

        # TODO: Support other BIP-39 wordlist languages!
        return bip85.derive_mnemonic(root, bip85_num_words, bip85_index)
        

    ### override operators    
    def __eq__(self, other):
        if isinstance(other, Seed):
            return self.seed_bytes == other.seed_bytes
        return False




    # ----------------- BIP-352 Silent Payments support -----------------
    def _derive_bip352_key(self, is_scanning_key: bool = True, account: int = 0, network: str = SettingsConstants.MAINNET):
        """
        Derives the BIP-352 scanning or signing key.
        see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki#key-derivation
        
        Args:
            is_scanning_key (bool): True for scanning key, False for signing key
            account (int): Account number (0-based)
            network (str): Network type (mainnet/testnet)
            
        Returns:
            HDKey: The derived key
        """
        purpose = 352  # per BIP-352 spec
        coin_type = 0 if network == SettingsConstants.MAINNET else 1  # mainnet coins vs testnet coins
        key_type = 1 if is_scanning_key else 0  # per BIP-352 spec; scanning key vs spending key
        derivation_path = f"m/{purpose}'/{coin_type}'/{account}'/{key_type}'/0"
        root = bip32.HDKey.from_seed(self.seed_bytes, version=NETWORKS[SettingsConstants.map_network_to_embit(network)]["xprv"])
        return root.derive(derivation_path)

    def derive_bip352_scanning_key(self, account: int = 0, network: str = SettingsConstants.MAINNET):
        """
        Derives the BIP-352 scanning key for the specified account and network.
        
        Args:
            account (int): Account number (0-based)
            network (str): Network type (mainnet/testnet)
            
        Returns:
            HDKey: The derived scanning key
        """
        return self._derive_bip352_key(is_scanning_key=True, account=account, network=network)

    def derive_bip352_signing_key(self, account: int = 0, network: str = SettingsConstants.MAINNET):
        """
        Derives the BIP-352 signing key for the specified account and network.
        
        Args:
            account (int): Account number (0-based)
            network (str): Network type (mainnet/testnet)
            
        Returns:
            HDKey: The derived signing key
        """
        return self._derive_bip352_key(is_scanning_key=False, account=account, network=network)

    def generate_bip352_silent_payment_address(self, account: int = 0, network: str = SettingsConstants.MAINNET):
        """
        Generates a BIP-352 Silent Payment address for the specified account and network.
        
        Args:
            account (int): Account number (0-based)
            network (str): Network type (mainnet/testnet)
            
        Returns:
            str: The Silent Payment address
        """
        from seedsigner.helpers import embit_utils
        scanning_pk = self.derive_bip352_scanning_key(account=account, network=network)
        signing_pk = self.derive_bip352_signing_key(account=account, network=network)
        scanning_pubkey = scanning_pk.get_public_key()
        signing_pubkey = signing_pk.get_public_key()
        
        logger.debug(f"Scanning pubkey: {scanning_pubkey.serialize().hex()}")
        logger.debug(f"Signing pubkey: {signing_pubkey.serialize().hex()}")
        
        return embit_utils.encode_silent_payment_address(scanning_pubkey, signing_pubkey, embit_network=SettingsConstants.map_network_to_embit(network))

    def export_bip352_keys(self, account: int = 0, network: str = SettingsConstants.MAINNET):
        """
        Exports the BIP-352 scanning and signing keys for the specified account and network.
        
        Args:
            account (int): Account number (0-based)
            network (str): Network type (mainnet/testnet)
            
        Returns:
            dict: Dictionary containing the scanning and signing keys
        """
        scanning_key = self.derive_bip352_scanning_key(account=account, network=network)
        signing_key = self.derive_bip352_signing_key(account=account, network=network)
        
        return {
            "scanning_key": scanning_key.to_base58(),
            "signing_key": signing_key.to_base58(),
            "account": account,
            "network": network
        }

    # ----------------- BIP-352 Silent Payments support -----------------

class ElectrumSeed(Seed):

    def _generate_seed(self):
        if len(self._mnemonic) != 12:
            raise InvalidSeedException(f"Unsupported Electrum seed length: {len(self._mnemonic)}")

        s = hmac.digest(b"Seed version", self.mnemonic_str.encode('utf8'), hashlib.sha512).hex()
        prefix = s[0:3]

        # only support Electrum Segwit version for now
        if SettingsConstants.ELECTRUM_SEED_SEGWIT == prefix:
            self.seed_bytes=hashlib.pbkdf2_hmac('sha512', self.mnemonic_str.encode('utf-8'), b'electrum' + self._passphrase.encode('utf-8'), iterations = SettingsConstants.ELECTRUM_PBKDF2_ROUNDS)

        else:
            raise InvalidSeedException(f"Unsupported Electrum seed format: {prefix}")


    def set_passphrase(self, passphrase: str, regenerate_seed: bool = True):
        if passphrase:
            self._passphrase = ElectrumSeed.normalize_electrum_passphrase(passphrase)
        else:
            # Passphrase must always have a string value, even if it's just the empty
            # string.
            self._passphrase = ""

        if regenerate_seed:
            # Regenerate the internal seed since passphrase changes the result
            self._generate_seed()


    @staticmethod
    def normalize_electrum_passphrase(passphrase : str) -> str:
        passphrase = unicodedata.normalize('NFKD', passphrase)
        # lower
        passphrase = passphrase.lower()
        # normalize whitespaces
        passphrase = u' '.join(passphrase.split())
        return passphrase


    @property
    def script_override(self) -> str:
        return SettingsConstants.NATIVE_SEGWIT


    def derivation_override(self, sig_type: str = SettingsConstants.SINGLE_SIG) -> str:
        return "m/0h" if sig_type == SettingsConstants.SINGLE_SIG else "m/1h"


    def detect_version(self, derivation_path: str, network: str = SettingsConstants.MAINNET, sig_type: str = SettingsConstants.SINGLE_SIG) -> str:
        embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]
        return embit_network["zpub"] if sig_type == SettingsConstants.SINGLE_SIG else embit_network["Zpub"]


    @property
    def passphrase_label(self) -> str:
        return SettingsConstants.LABEL__CUSTOM_EXTENSION


    @property
    def seedqr_supported(self) -> bool:
        return False


    @property
    def bip85_supported(self) -> bool:
        return False
