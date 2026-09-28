import argparse
import os
import sys
import uuid
from pathlib import Path

if __package__:
    from .crypto import decrypt_stream_with_filename
    from .paths import contained, media_suffix, publish_file, snapshot
else:
    from crypto import decrypt_stream_with_filename
    from paths import contained, media_suffix, publish_file, snapshot


def restored_filename(source, temporary, filename):
    if filename is None:
        filename = source.stem
        with temporary.open("rb") as stream:
            suffix = media_suffix(stream.read(8192))
        if suffix:
            existing = Path(filename).suffix.lower()
            existing = {".jpeg": ".jpg", ".tiff": ".tif", ".m4v": ".mp4"}.get(existing, existing)
            if existing != suffix:
                filename += suffix
        elif not Path(filename).suffix:
            filename += ".bin"
    if not filename or filename in (".", "..") or filename.endswith((".", " ")) or any(ord(char) < 32 or char in '/\\<>:"|?*' for char in filename):
        raise ValueError("Unsafe original filename; specify an explicit --output filename")
    return filename


def decrypt_file(source, destination=None):
    source = Path(source)
    destination = Path(destination) if destination is not None else source.parent
    automatic = destination.is_dir()
    if not automatic and destination.exists():
        raise FileExistsError(f"Will not overwrite {destination}")
    directory = (destination if automatic else destination.parent).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / (".privacy-decrypt-" + uuid.uuid4().hex + ".part")
    created = False
    try:
        with open(source, "rb") as encrypted, open(temporary, "xb") as plain:
            created = True
            _, filename = decrypt_stream_with_filename(encrypted, plain)
            plain.flush()
            os.fsync(plain.fileno())
        if automatic:
            name = Path(restored_filename(source, temporary, filename))
            counter = 0
            while True:
                candidate = name.name if counter == 0 else f"{name.stem}_{counter}{name.suffix}"
                destination = contained(directory, directory / candidate)
                if destination is None:
                    raise ValueError("Restored filename points outside the output directory or to a link")
                try:
                    publish_file(temporary, destination)
                    break
                except FileExistsError:
                    counter += 1
        else:
            publish_file(temporary, destination)
        return destination
    finally:
        if created:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Decode PrivacyGuard time-derived files; no key or configuration required")
    commands = parser.add_subparsers(dest="command", required=True)
    decrypt = commands.add_parser("decrypt")
    decrypt.add_argument("--input", required=True, type=Path)
    decrypt.add_argument("--output", type=Path, help="Optional output file or existing directory; defaults to restored names beside the input (directory input: decrypted subdirectory)")
    args = parser.parse_args(argv)
    source = args.input.resolve()
    if source.is_file():
        destination = decrypt_file(source, args.output)
        print(f"Decrypted: {destination}")
        return 0
    if not source.is_dir():
        raise FileNotFoundError(source)
    output = (args.output or source / "decrypted").resolve()
    files, _ = snapshot(source)
    output.mkdir(parents=True, exist_ok=True)
    failures = 0
    for relative in sorted(files):
        if not relative.endswith(".cpriv"):
            continue
        try:
            directory = output / Path(relative).parent
            if directory != output and contained(output, directory) is None:
                raise ValueError("Output subdirectory escaped its root or became a link")
            directory.mkdir(parents=True, exist_ok=True)
            destination = decrypt_file(source / relative, directory)
            print(f"Decrypted: {destination}")
        except Exception as error:
            print(f"Failed: {relative}: {type(error).__name__}: {error}", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"PrivacyGuard: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
