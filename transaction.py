import hashlib
import json
from dataclasses import dataclass, field
from typing import List, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature
)
from cryptography.exceptions import InvalidSignature


@dataclass
class TransactionInput:
    previous_tx_id: str
    output_index: int
    signature: Optional[bytes] = None
    public_key: Optional[bytes] = None

    def serialize(self) -> dict:
        return {
            'previous_tx_id': self.previous_tx_id,
            'output_index': self.output_index,
            'signature': self.signature.hex() if self.signature else None,
            'public_key': self.public_key.hex() if self.public_key else None
        }


@dataclass
class TransactionOutput:
    amount: float
    recipient_hash: bytes

    def serialize(self) -> dict:
        return {
            'amount': self.amount,
            'recipient_hash': self.recipient_hash.hex()
        }


class Transaction:
    def __init__(self):
        self.inputs: List[TransactionInput] = []
        self.outputs: List[TransactionOutput] = []
        self.version: int = 1
        self.locktime: int = 0
        self._id: Optional[str] = None

    @property
    def id(self) -> str:
        if not self._id:
            self._id = self._calculate_id()
        return self._id

    def add_input(self, tx_input: TransactionInput):
        self.inputs.append(tx_input)
        self._id = None

    def add_output(self, tx_output: TransactionOutput):
        self.outputs.append(tx_output)
        self._id = None

    def sign_input(self, input_index: int, private_key: ec.EllipticCurvePrivateKey):
        if input_index >= len(self.inputs):
            raise IndexError("Input index out of range")

        tx_input = self.inputs[input_index]
        data = self._signature_data(input_index)

        tx_input.signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        tx_input.public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        self._id = None

    def verify(self) -> bool:
        if not self._check_balances():
            return False

        for i, tx_input in enumerate(self.inputs):
            if not self.verify_input(i):
                return False
        return True

    def verify_input(self, input_index: int) -> bool:
        tx_input = self.inputs[input_index]
        if not tx_input.signature or not tx_input.public_key:
            return False

        try:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                tx_input.public_key
            )
            public_key.verify(
                tx_input.signature,
                self._signature_data(input_index),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except (InvalidSignature, ValueError):
            return False

    def _signature_data(self, input_index: int) -> bytes:
        tx_input = self.inputs[input_index]
        data = {
            'version': self.version,
            'inputs': [inp.serialize() for i, inp in enumerate(self.inputs) if i != input_index],
            'outputs': [out.serialize() for out in self.outputs],
            'locktime': self.locktime,
            'input_to_sign': {
                'previous_tx_id': tx_input.previous_tx_id,
                'output_index': tx_input.output_index
            }
        }
        return json.dumps(data, sort_keys=True).encode()

    def _calculate_id(self) -> str:
        data = {
            'version': self.version,
            'inputs': [inp.serialize() for inp in self.inputs],
            'outputs': [out.serialize() for out in self.outputs],
            'locktime': self.locktime
        }
        return hashlib.sha256(json.dumps(data).encode()).hexdigest()

    def _check_balances(self) -> bool:
        return True

    def serialize(self) -> str:
        return json.dumps({
            'id': self.id,
            'version': self.version,
            'inputs': [inp.serialize() for inp in self.inputs],
            'outputs': [out.serialize() for out in self.outputs],
            'locktime': self.locktime
        })

    @classmethod
    def deserialize(cls, json_str: str) -> 'Transaction':
        data = json.loads(json_str)
        tx = cls()
        tx.version = data['version']
        tx.locktime = data['locktime']

        for inp in data['inputs']:
            tx_input = TransactionInput(
                previous_tx_id=inp['previous_tx_id'],
                output_index=inp['output_index'],
                signature=bytes.fromhex(inp['signature']) if inp['signature'] else None,
                public_key=bytes.fromhex(inp['public_key']) if inp['public_key'] else None
            )
            tx.add_input(tx_input)

        for out in data['outputs']:
            tx_output = TransactionOutput(
                amount=out['amount'],
                recipient_hash=bytes.fromhex(out['recipient_hash'])
            )
            tx.add_output(tx_output)

        tx._id = data['id']
        return tx