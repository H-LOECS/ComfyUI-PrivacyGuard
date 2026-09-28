import mimetypes
import os
import stat
import time
from pathlib import Path

if os.name == "nt":
    import ctypes
    from ctypes import wintypes
    import msvcrt

    _create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    _create_file.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    _create_file.restype = wintypes.HANDLE
    _close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    _close_handle.argtypes = (wintypes.HANDLE,)
    _close_handle.restype = wintypes.BOOL


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".avif", ".heic", ".heif", ".jxl", ".exr", ".hdr", ".ppm", ".pgm", ".pbm", ".ico"}
VIDEO_EXTENSIONS = {".mp4", ".m4v", ".mov", ".mkv", ".webm", ".avi", ".mpg", ".mpeg", ".ts", ".m2ts", ".mjpeg", ".mjpg", ".wmv", ".flv", ".ogv"}


def open_shared_read(path):
    if os.name != "nt":
        return open(path, "rb")
    # Keep a read handle valid across PrivacyGuard's rename/delete, as on POSIX.
    handle = _create_file(str(path), 0x80000000, 0x7, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except OSError:
        _close_handle(handle)
        raise
    return os.fdopen(descriptor, "rb")


def is_image(path):
    content_type = mimetypes.guess_type(str(path), strict=False)[0]
    return Path(path).suffix.lower() in IMAGE_EXTENSIONS or bool(content_type and content_type.startswith("image/"))


def is_media(path):
    suffix = Path(path).suffix.lower()
    if suffix in IMAGE_EXTENSIONS | VIDEO_EXTENSIONS:
        return True
    content_type = mimetypes.guess_type(str(path), strict=False)[0]
    return bool(content_type and content_type.split("/", 1)[0] in ("image", "video"))


def identity(path):
    try:
        value = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(value.st_mode):
        return None
    return [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def linked(path):
    value = os.lstat(path)
    return stat.S_ISLNK(value.st_mode) or bool(getattr(value, "st_file_attributes", 0) & 0x400)


def contained(root, path):
    root = Path(root).resolve()
    path = Path(os.path.abspath(path))
    try:
        relative = path.relative_to(root)
    except ValueError:
        return None
    if not relative.parts:
        return None
    current = root
    for part in relative.parts:
        current = current / part
        try:
            if linked(current):
                return None
        except FileNotFoundError:
            continue
    return path


def snapshot(root):
    files = {}
    directories = []
    root = Path(root)
    if not root.exists():
        return files, directories
    for parent, names, filenames in os.walk(root, followlinks=False):
        names[:] = [name for name in names if not linked(Path(parent) / name)]
        for name in names:
            directories.append((Path(parent) / name).relative_to(root).as_posix())
        for name in filenames:
            path = contained(root, Path(parent) / name)
            if path is None:
                continue
            version = identity(path)
            if version is not None:
                files[path.relative_to(root).as_posix()] = version
    return files, directories


def remove_version(root, relative, version):
    path = contained(root, Path(root) / relative)
    if path is None:
        raise ValueError("File path escaped its recorded directory or became a link")
    for attempt in range(3):
        current = identity(path)
        if current is None:
            return "missing"
        if current != version:
            return "replaced"
        try:
            path.unlink()
            sync_directory(path.parent)
            return "deleted"
        except PermissionError:
            if attempt == 2:
                raise
            time.sleep((0.1, 0.3)[attempt])


def sync_directory(directory):
    if os.name == "nt":
        return
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish_file(source, destination):
    # link() provides an atomic no-clobber commit on Windows and POSIX.
    os.link(source, destination)
    sync_directory(Path(destination).parent)
    os.unlink(source)
    sync_directory(Path(source).parent)


def media_suffix(data):
    for signature, suffix in (
        (b"\x89PNG\r\n\x1a\n", ".png"), (b"\xff\xd8\xff", ".jpg"),
        (b"GIF87a", ".gif"), (b"GIF89a", ".gif"), (b"BM", ".bmp"),
        (b"II*\x00", ".tif"), (b"MM\x00*", ".tif"),
        (b"FLV", ".flv"), (b"\x76\x2f\x31\x01", ".exr"),
        (b"#?RADIANCE", ".hdr"), (b"\x00\x00\x01\x00", ".ico"),
    ):
        if data.startswith(signature):
            return suffix
    if data[:4] == b"RIFF":
        return {b"WEBP": ".webp", b"AVI ": ".avi"}.get(data[8:12])
    if data[4:8] == b"ftyp":
        box_size = int.from_bytes(data[:4], "big")
        brands = {data[8:12]} | {data[i:i + 4] for i in range(16, min(box_size, len(data)), 4)}
        if brands & {b"avif", b"avis"}:
            return ".avif"
        if brands & {b"heic", b"heix", b"hevc", b"hevx"}:
            return ".heic"
        if brands & {b"mif1", b"msf1"}:
            return ".heif"
        return ".mov" if b"qt  " in brands else ".mp4"
    if data.startswith(b"\x1a\x45\xdf\xa3"):
        return ".webm" if b"webm" in data else ".mkv"
    return None
