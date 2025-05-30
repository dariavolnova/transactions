import unittest
import hashlib
import os
from transaction import Transaction, TransactionInput, TransactionOutput
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)


class TestTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = ec.generate_private_key(ec.SECP256R1())
        cls.public_key = cls.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        cls.alt_private_key = ec.generate_private_key(ec.SECP256R1())
        cls.alt_public_key = cls.alt_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    def setUp(self):
        self.tx = Transaction()
        self.tx_input = TransactionInput(
            previous_tx_id="prev_tx_001",
            output_index=0
        )
        self.tx_output = TransactionOutput(
            amount=10.0,
            recipient_hash=hashlib.sha256(self.public_key).digest()
        )

    def test_empty_transaction(self):
        self.assertEqual(len(self.tx.inputs), 0)
        self.assertEqual(len(self.tx.outputs), 0)
        self.assertEqual(self.tx.version, 1)
        self.assertEqual(self.tx.locktime, 0)

    def test_add_input_output(self):
        self.tx.add_input(self.tx_input)
        self.tx.add_output(self.tx_output)

        self.assertEqual(len(self.tx.inputs), 1)
        self.assertEqual(len(self.tx.outputs), 1)
        self.assertEqual(self.tx.inputs[0].previous_tx_id, "prev_tx_001")
        self.assertEqual(self.tx.outputs[0].amount, 10.0)

    def test_transaction_id_changes(self):
        self.tx.add_input(self.tx_input)
        id1 = self.tx.id

        self.tx.add_output(self.tx_output)
        id2 = self.tx.id

        self.assertNotEqual(id1, id2)

    def test_sign_and_verify_input(self):
        self.tx.add_input(self.tx_input)
        self.tx.add_output(self.tx_output)

        self.tx.sign_input(0, self.private_key)

        self.assertTrue(self.tx.verify_input(0))
        self.assertTrue(self.tx.verify())

    def test_verification_fails_when_tampered(self):
        self.tx.add_input(self.tx_input)
        self.tx.add_output(self.tx_output)
        self.tx.sign_input(0, self.private_key)

        self.tx.outputs[0].amount = 20.0

        self.assertFalse(self.tx.verify_input(0))
        self.assertFalse(self.tx.verify())

    def test_wrong_key_verification_fails(self):
        self.tx.add_input(self.tx_input)
        self.tx.add_output(self.tx_output)

        self.tx.sign_input(0, self.private_key)

        self.tx.inputs[0].public_key = self.alt_public_key

        self.assertFalse(self.tx.verify_input(0))

    def test_serialization_roundtrip(self):
        self.tx.add_input(self.tx_input)
        self.tx.add_output(self.tx_output)
        self.tx.sign_input(0, self.private_key)

        serialized = self.tx.serialize()
        new_tx = Transaction.deserialize(serialized)

        self.assertEqual(self.tx.id, new_tx.id)
        self.assertEqual(len(new_tx.inputs), 1)
        self.assertEqual(len(new_tx.outputs), 1)
        self.assertTrue(new_tx.verify_input(0))

    def test_sign_unexisting_input_fails(self):
        with self.assertRaises(IndexError):
            self.tx.sign_input(0, self.private_key)


if __name__ == "__main__":
    unittest.main()