import asyncio
import concurrent.futures
from contextlib import ExitStack
import io
import logging
import mimetypes
import ntpath
import os
from pathlib import Path
import re
import threading
from urllib.parse import quote

from aiohttp import web
from nacl.exceptions import CryptoError
from PIL import Image

from . import crypto
from .guard import PrivacyError
from .paths import contained, identity, is_media, media_suffix, open_shared_read


def resolve_request(query, roots):
    filename = query.get("filename", "")
    if not filename or filename.startswith("blake3:"):
        return None
    kind = query.get("type", "output")
    for annotation in ("input", "output", "temp"):
        if filename.endswith(f" [{annotation}]"):
            filename = filename[:-(len(annotation) + 3)]
            kind = annotation
            break
    if kind not in ("temp", "output") or not is_media(filename):
        return None
    if not filename or ".." in filename or any(c in filename for c in "/\\:\x00\r\n"):
        raise web.HTTPBadRequest(text="Invalid media filename")
    subfolder = query.get("subfolder", "")
    if ntpath.isabs(subfolder) or ntpath.splitdrive(subfolder)[0] or any(c in subfolder for c in ":\x00"):
        raise web.HTTPForbidden(text="Invalid media subfolder")
    relative = Path(subfolder.replace("\\", "/")) / filename
    if ".." in relative.parts or contained(roots[kind], roots[kind] / relative) is None:
        raise web.HTTPForbidden(text="Media path escaped its directory or became a link")
    return kind, relative.as_posix()


def byte_range(value, size):
    if value is None:
        return 0, size, 200
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", value)
    if match:
        first, last = match.groups()
        if first:
            start = int(first)
            end = min(size, int(last) + 1) if last else size
        elif last and int(last) > 0:
            start, end = max(0, size - int(last)), size
        else:
            start, end = 0, 0
        if 0 <= start < end <= size:
            return start, end, 206
    raise web.HTTPRequestRangeNotSatisfiable(headers={"Content-Range": f"bytes */{size}"})


def transform_image(content, query):
    channel = query.get("channel", "rgba")
    with Image.open(content) as image:
        if "preview" in query:
            options = query["preview"].split(";")
            format_name = options[0]
            if format_name not in ("webp", "jpeg") or "a" in query.get("channel", ""):
                format_name = "webp"
            quality = int(options[-1]) if options[-1].isdigit() else 90
            if format_name == "jpeg" or channel == "rgb":
                image = image.convert("RGB")
            output = io.BytesIO()
            image.save(output, format=format_name, quality=quality)
            return output.getvalue(), "image/" + format_name
        if channel == "rgb":
            image = image.convert("RGB")
        else:
            alpha = image.getchannel("A") if image.mode == "RGBA" else Image.new("L", image.size, 255)
            image = Image.new("RGBA", image.size)
            image.putalpha(alpha)
        output = io.BytesIO()
        image.save(output, format="PNG")
        return output.getvalue(), "image/png"


class ViewService:
    def __init__(self, guard):
        self.guard = guard
        self.slots = asyncio.Semaphore(2)

    def legacy_media(self, kind, relative, stop):
        root = self.guard.roots[kind]
        source = self.guard.artifact(relative, kind)
        if not source.parent.is_dir():
            return None
        known = {row[0] for row in self.guard.rows("SELECT file FROM media WHERE kind=?", (kind,))}
        matches = []
        for path in source.parent.iterdir():
            check_cancelled(stop)
            if path.suffix != ".cpriv" or path.relative_to(root).as_posix() in known:
                continue
            if path.name not in (source.stem + ".cpriv", source.name + ".cpriv") and not path.name.startswith(source.stem + "."):
                continue
            if contained(root, path) is None or identity(path) is None:
                continue
            before = identity(path)
            with open_shared_read(path) as stream:
                reader = crypto.StreamReader(stream)
                if reader.filename is not None and reader.filename != source.name:
                    continue
                size, prefix = 0, b""
                for block in reader:
                    check_cancelled(stop)
                    size += len(block)
                    if len(prefix) < 8192:
                        prefix += block[:8192 - len(prefix)]
            if identity(path) != before:
                raise PrivacyError("Legacy ciphertext changed during verification")
            if reader.filename is None:
                suffix = {".jpeg": ".jpg", ".tiff": ".tif", ".m4v": ".mp4"}.get(source.suffix.lower(), source.suffix.lower())
                if path.name != source.name + ".cpriv" and media_suffix(prefix) != suffix:
                    continue
            matches.append((path, size))
        if len(matches) != 1:
            return None
        path, size = matches[0]
        self.guard.remember_media(kind, relative, path.relative_to(root).as_posix(), size)
        return path, size

    def produce(self, kind, relative, query, range_header, head, emit, stop):
        try:
            with ExitStack() as resources:
                while not self.guard.processing_lock.acquire(timeout=0.1):
                    check_cancelled(stop)
                lock = ExitStack()
                lock.callback(self.guard.processing_lock.release)
                resources.enter_context(lock)
                check_cancelled(stop)
                path = self.guard.artifact(relative, kind)
                encrypted = not path.is_file()
                if encrypted:
                    mapped = self.guard.mapped_media(kind, relative) or self.legacy_media(kind, relative, stop)
                    if mapped is None:
                        raise web.HTTPNotFound(text="Media is no longer available")
                    path, expected_size = mapped
                stream = resources.enter_context(open_shared_read(path))
                before = os.fstat(stream.fileno())
                lock.close()
                transformed = "preview" in query or query.get("channel") in ("rgb", "a")
                content = resources.enter_context(io.BytesIO()) if transformed else None
                if encrypted:
                    size = 0
                    for block in crypto.StreamReader(stream):
                        check_cancelled(stop)
                        size += len(block)
                        if content is not None:
                            content.write(block)
                    after = os.fstat(stream.fileno())
                    if size != expected_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                        raise PrivacyError("Ciphertext changed during verification")
                    stream.seek(0)
                    blocks = crypto.StreamReader(stream)
                else:
                    size = before.st_size
                    blocks = iter(lambda: stream.read(crypto.CHUNK_SIZE), b"")
                    if content is not None:
                        for block in blocks:
                            check_cancelled(stop)
                            content.write(block)
                content_type = mimetypes.guess_type(relative)[0] or "application/octet-stream"
                if transformed:
                    content.seek(0)
                    check_cancelled(stop)
                    body, content_type = transform_image(content, query)
                    size, blocks = len(body), iter((body,))
                # If-Range cannot match a validator: send the full representation.
                start, end, status = byte_range(range_header, size)
                headers = {
                    "Content-Type": content_type,
                    "Content-Length": str(end - start),
                    "Content-Disposition": "inline; filename*=UTF-8''" + quote(Path(relative).name, safe=""),
                    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                    "Accept-Ranges": "bytes",
                }
                if status == 206:
                    headers["Content-Range"] = f"bytes {start}-{end - 1}/{size}"
                if content_type in ("image/svg+xml", "application/xml", "text/xml"):
                    headers["Content-Disposition"] = headers["Content-Disposition"].replace("inline;", "attachment;", 1)
                emit((status, headers))
                if not head:
                    position = 0
                    for block in blocks:
                        check_cancelled(stop)
                        following = position + len(block)
                        if following > start and position < end:
                            emit(block[max(0, start - position):min(len(block), end - position)])
                        position = following
                        if position >= end:
                            break
            emit(None)
        except concurrent.futures.CancelledError:
            return
        except Exception as error:
            if not stop.is_set():
                emit(error)

    async def handle(self, request, kind, relative):
        async with self.slots:
            loop = asyncio.get_running_loop()
            queue = asyncio.Queue(maxsize=1)
            stop = threading.Event()

            def emit(value):
                check_cancelled(stop)
                pending = asyncio.run_coroutine_threadsafe(queue.put(value), loop)
                try:
                    while True:
                        try:
                            pending.result(timeout=0.1)
                            return
                        except concurrent.futures.TimeoutError:
                            check_cancelled(stop)
                finally:
                    if not pending.done():
                        pending.cancel()

            async def receive():
                while True:
                    if request.transport is None or request.transport.is_closing():
                        raise ConnectionResetError("Media client disconnected")
                    try:
                        return await asyncio.wait_for(queue.get(), 0.1)
                    except asyncio.TimeoutError:
                        if worker.done() and queue.empty():
                            await worker
                            raise RuntimeError("Media worker exited before completing its response")

            range_header = request.headers.get("Range") if "If-Range" not in request.headers and request.method != "HEAD" else None
            worker = asyncio.create_task(asyncio.to_thread(self.produce, kind, relative, dict(request.query), range_header, request.method == "HEAD", emit, stop))
            response = None
            try:
                first = await receive()
                if isinstance(first, Exception):
                    raise first
                status, headers = first
                response = web.StreamResponse(status=status, headers=headers)
                await response.prepare(request)
                while True:
                    block = await receive()
                    if block is None:
                        break
                    if isinstance(block, Exception):
                        raise block
                    await response.write(block)
                await response.write_eof()
                return response
            except web.HTTPException as error:
                error.headers["Cache-Control"] = "no-store"
                raise
            except FileNotFoundError:
                raise web.HTTPNotFound(text="Media is no longer available", headers={"Cache-Control": "no-store"})
            except (ConnectionResetError, BrokenPipeError):
                raise
            except (ValueError, CryptoError, PrivacyError, OSError) as error:
                logging.error("PrivacyGuard view failed: %s", error)
                if response is not None and response.prepared:
                    if request.transport is not None:
                        request.transport.close()
                    raise
                raise web.HTTPInternalServerError(text="PrivacyGuard could not verify or read this media", headers={"Cache-Control": "no-store"})
            finally:
                stop.set()
                await asyncio.shield(worker)


def check_cancelled(stop):
    if stop.is_set():
        raise concurrent.futures.CancelledError()
