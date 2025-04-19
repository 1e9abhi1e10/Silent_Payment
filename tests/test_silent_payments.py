import unittest
import logging
from embit import bip32, bip39
from embit.networks import NETWORKS
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.models.psbt_parser import PSBTParser
from embit.psbt import PSBT

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class TestSilentPayments(unittest.TestCase):
    def setUp(self):
        # Create a test seed
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        self.seed = Seed(mnemonic=mnemonic.split())
        self.network = SettingsConstants.MAINNET

    def test_derive_bip352_keys(self):
        """Test deriving BIP-352 scanning and signing keys"""
        # Test scanning key derivation
        scanning_key = self.seed._derive_bip352_key(is_scanning_key=True, account=0, network=self.network)
        self.assertIsInstance(scanning_key, bip32.HDKey)
        pubkey_hex = scanning_key.derive("m/352'/0'/0'/1'/0").get_public_key().serialize().hex()
        logger.debug(f"Scanning pubkey: {pubkey_hex}")
        self.assertEqual(pubkey_hex, 
                        "02c7e8767b7f8906fc5c91d64b4ac6900c3cbfe0d2e00c809e42652f5bead1236f")

        # Test signing key derivation
        signing_key = self.seed._derive_bip352_key(is_scanning_key=False, account=0, network=self.network)
        self.assertIsInstance(signing_key, bip32.HDKey)
        pubkey_hex = signing_key.derive("m/352'/0'/0'/0'/0").get_public_key().serialize().hex()
        logger.debug(f"Signing pubkey: {pubkey_hex}")
        self.assertEqual(pubkey_hex,
                        "03728850411bfe086adb4a175100c06646ecf546cf48b67f6d58f5257e78978a21")

    def test_generate_silent_payment_address(self):
        """Test generating a Silent Payment address"""
        address = self.seed.generate_bip352_silent_payment_address(account=0, network=self.network)
        logger.debug(f"Generated address: {address}")
        self.assertIsInstance(address, str)
        self.assertTrue(address.startswith('sp1'))  # Silent Payment addresses start with 'sp1'

    def test_export_bip352_keys(self):
        """Test exporting BIP-352 keys"""
        keys = self.seed.export_bip352_keys(account=0, network=self.network)
        self.assertIsInstance(keys, dict)
        self.assertIn('scanning_key', keys)
        self.assertIn('signing_key', keys)
        self.assertIn('account', keys)
        self.assertIn('network', keys)
        self.assertEqual(keys['account'], 0)
        self.assertEqual(keys['network'], self.network)

    def test_psbt_silent_payment_parsing(self):
        """Test parsing Silent Payment outputs from PSBTs"""
        # Create a test PSBT with Silent Payment output
        psbt = PSBT()
        psbt.outputs = []
        output = type('TestOutput', (), {
            'silent_payment_data': type('TestSPData', (), {
                'scanning_pubkey': bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
                'signing_pubkey': bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
            }),
            'amount': 100000,
            'script_pubkey': bytes.fromhex('0014751e76e8199196d454941c45d1b3a323f1433bd6')
        })()
        psbt.outputs.append(output)

        # Test parsing the Silent Payment output
        output_data = PSBTParser.parse_silent_payment_output(psbt, 0)
        self.assertIsInstance(output_data, dict)
        self.assertIn('scanning_pubkey', output_data)
        self.assertIn('signing_pubkey', output_data)
        self.assertIn('amount', output_data)
        self.assertEqual(output_data['amount'], 100000)

    def test_verify_silent_payment_input(self):
        """Test verifying Silent Payment inputs"""
        # Create a test PSBT with Silent Payment input
        psbt = PSBT()
        psbt.inputs = []
        input = type('TestInput', (), {
            'bip32_derivations': {
                bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'): 
                type('TestDerivation', (), {
                    'fingerprint': bytes.fromhex('00000000'),
                    'path': [352 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0]
                })
            }
        })()
        psbt.inputs.append(input)

        # Test verifying the input
        result = PSBTParser.verify_silent_payment_input(psbt, self.seed, self.network)
        self.assertIsInstance(result, bool)

if __name__ == '__main__':
    unittest.main() 