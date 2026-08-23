"""Tests for the canonical numeric public-ID codec."""

import secrets

import pytest
from app.public_ids import (
    decode_public_id_payload,
    encode_public_id_payload,
    MAX_PUBLIC_ID,
    PUBLIC_ID_PAYLOAD_LENGTH,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0000000000000"),
        (1, "0000000000001"),
        (31, "000000000000Z"),
        (32, "0000000000010"),
        (33, "0000000000011"),
        (1023, "00000000000ZZ"),
        (1024, "0000000000100"),
        (MAX_PUBLIC_ID, "7ZZZZZZZZZZZZ"),
    ],
)
def test_public_id_payload_boundaries_round_trip(value: int, expected: str) -> None:
    """Encode boundary values with fixed width and decode them losslessly."""
    payload = encode_public_id_payload(value)

    assert payload == expected
    assert len(payload) == PUBLIC_ID_PAYLOAD_LENGTH
    assert payload == payload.upper()
    assert decode_public_id_payload(payload) == value


def test_random_public_id_payloads_round_trip() -> None:
    """Round-trip randomly selected values across the signed-int64 range."""
    for _ in range(100):
        value = secrets.randbelow(MAX_PUBLIC_ID + 1)
        assert decode_public_id_payload(encode_public_id_payload(value)) == value


@pytest.mark.parametrize("value", [-1, MAX_PUBLIC_ID + 1, True, 1.0, "1"])
def test_public_id_payload_encoding_rejects_invalid_values(value: object) -> None:
    """Reject negative, overflowing, and non-integer values."""
    with pytest.raises(ValueError, match="Public identifier"):
        encode_public_id_payload(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "payload",
    [
        "000000000000",
        "00000000000000",
        "000000000000a",
        "000000000000I",
        "000000000000L",
        "000000000000O",
        "000000000000U",
        "000000000000-",
        "000000000000_",
        "000000000000 ",
        "+000000000000",
        "8000000000000",
        "7ZZZZZZZZZZZ*",
    ],
)
def test_public_id_payload_decoding_rejects_noncanonical_values(payload: str) -> None:
    """Accept no aliases, alternate casing, separators, or overflowing values."""
    with pytest.raises(ValueError, match="Public identifier"):
        decode_public_id_payload(payload)
