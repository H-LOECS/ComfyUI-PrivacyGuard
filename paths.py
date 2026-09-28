import mimetypes
import os
import stat
import time
from pathlib import Path


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".avif", ".heic", ".heif", ".jxl", ".exr", ".hdr", ".ppm", ".pgm", ".pbm", ".ico"}
VIDEO_EXTENSIONS = {".mp4", ".m4v", ".mov", ".mkv", ".webm", ".avi", ".mpg", ".mpeg", ".ts", ".m2ts", ".mjpeg", ".mjpg", ".wmv", ".flv", ".ogv"}


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
