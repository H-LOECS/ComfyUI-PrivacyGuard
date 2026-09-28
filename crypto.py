import base64
import hashlib
import json
import os
import struct
import time

from nacl import bindings as sodium


MAGIC = b"CPRIV\x00\x03\x00"
V2_MAGIC = b"CPRIV\x00\x02\x00"
LEGACY_MAGIC = b"CPRIV\x00\x01\x00"
CHUNK_SIZE = 4 * 1024 * 1024
HEADER_LIMIT = 4096
LENGTH = struct.Struct(">I")
SUITE = "secretstream-xchacha20poly1305-time"
TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_PUSH = sodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH
TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
OVERHEAD = sodium.crypto_secretstream_xchacha20poly1305_ABYTES


class LegacyFormatError(ValueError):
    pass


def derive_key(timestamp_ns):
    # The timestamp is public. This deliberately provides obfuscation, not secrecy.
    return hashlib.sha256(b"PrivacyGuard/time/v2\x00" + timestamp_ns.encode("ascii")).digest()


def encode(data):
    return base64.b64encode(data).decode("ascii")


def decode(text):
    return base64.b64decode(text, validate=True)


def read_exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("Truncated encrypted file")
    return data


def read_header(stream):
    magic = read_exact(stream, len(MAGIC))
    if magic == LEGACY_MAGIC:
        raise LegacyFormatError("PrivacyGuard v1 file: use the original v1 decryption tool")
    if magic not in (MAGIC, V2_MAGIC):
        raise ValueError("Not a supported PrivacyGuard file")
    length_bytes = read_exact(stream, LENGTH.size)
    length = LENGTH.unpack(length_bytes)[0]
    if not 0 < length <= HEADER_LIMIT:
        raise ValueError("Invalid encrypted header length")
    raw = read_exact(stream, length)
    header = json.loads(raw)
    expected_version = 3 if magic == MAGIC else 2
    if header.get("version") != expected_version or header.get("suite") != SUITE or header.get("chunk_size") != CHUNK_SIZE:
        raise ValueError("Unsupported encrypted file format")
    timestamp_ns = header.get("timestamp_ns")
    if not isinstance(timestamp_ns, str) or not 1 <= len(timestamp_ns) <= 32 or not timestamp_ns.isascii() or not timestamp_ns.removeprefix("-").isdecimal():
        raise ValueError("Invalid encryption timestamp")
    stream_header = decode(header["stream_header"])
    if len(stream_header) != sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES:
        raise ValueError("Invalid stream header length")
    return header, magic + length_bytes + raw, stream_header


def _read_record(source, state, authenticated_header, maximum):
    length_bytes = read_exact(source, LENGTH.size)
    length = LENGTH.unpack(length_bytes)[0]
    if not OVERHEAD <= length <= maximum + OVERHEAD:
        raise ValueError("Invalid encrypted block length")
    block = read_exact(source, length)
    return sodium.crypto_secretstream_xchacha20poly1305_pull(state, block, authenticated_header + length_bytes)


def _write_record(destination, state, authenticated_header, plain, tag):
    length_bytes = LENGTH.pack(len(plain) + OVERHEAD)
    block = sodium.crypto_secretstream_xchacha20poly1305_push(state, plain, authenticated_header + length_bytes, tag)
    destination.write(length_bytes)
    destination.write(block)


def decrypt_stream(source, destination=None):
    digest, _ = decrypt_stream_with_filename(source, destination)
    return digest


def decrypt_stream_with_filename(source, destination=None):
    """Return the content digest and original filename after verifying the entire file."""
    header, authenticated_header, stream_header = read_header(source)
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, stream_header, derive_key(header["timestamp_ns"]))
    filename = None
    if header["version"] == 3:
        plain, tag = _read_record(source, state, authenticated_header, HEADER_LIMIT)
        if tag != TAG_PUSH:
            raise ValueError("Missing encrypted filename metadata")
        metadata = json.loads(plain)
        if not isinstance(metadata, dict) or set(metadata) != {"filename"}:
            raise ValueError("Invalid filename metadata")
        filename = metadata["filename"]
        if filename is not None and (not isinstance(filename, str) or not filename):
            raise ValueError("Invalid original filename")
    digest = hashlib.sha256()
    while True:
        plain, tag = _read_record(source, state, authenticated_header, CHUNK_SIZE)
        if tag == TAG_FINAL:
            if plain or source.read(1):
                raise ValueError("Invalid final block or trailing content")
            return digest.hexdigest(), filename
        if tag != TAG_MESSAGE or not plain:
            raise ValueError("Invalid data block")
        digest.update(plain)
        if destination is not None:
            destination.write(plain)


def encrypt_stream(source, destination, filename=None):
    metadata = json.dumps({"filename": filename}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(metadata) > HEADER_LIMIT:
        raise ValueError("Filename metadata is too large")
    timestamp_ns = str(time.time_ns())
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    stream_header = sodium.crypto_secretstream_xchacha20poly1305_init_push(state, derive_key(timestamp_ns))
    header = json.dumps({
        "version": 3, "suite": SUITE, "chunk_size": CHUNK_SIZE,
        "timestamp_ns": timestamp_ns,
        "stream_header": encode(stream_header),
    }, separators=(",", ":"), sort_keys=True).encode("utf-8")
    authenticated_header = MAGIC + LENGTH.pack(len(header)) + header
    destination.write(authenticated_header)
    _write_record(destination, state, authenticated_header, metadata, TAG_PUSH)
    digest = hashlib.sha256()
    while True:
        plain = source.read(CHUNK_SIZE)
        digest.update(plain)
        tag = TAG_MESSAGE if plain else TAG_FINAL
        _write_record(destination, state, authenticated_header, plain, tag)
        if tag == TAG_FINAL:
            break
    destination.flush()
    os.fsync(destination.fileno())
    return digest.hexdigest()


def file_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()
