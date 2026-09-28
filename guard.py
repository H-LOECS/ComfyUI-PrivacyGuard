import json
import sqlite3
import tempfile
import threading
import uuid
from pathlib import Path

from filelock import FileLock

from . import crypto
from .paths import contained, identity, is_image, is_media, publish_file, remove_version, snapshot


class PrivacyError(RuntimeError):
    pass


class Guard:
    def __init__(self, roots, state_directory):
        self.roots = {kind: Path(path).resolve() for kind, path in roots.items()}
        state_directory = Path(state_directory).resolve()
        locations = list(self.roots.values()) + [state_directory]
        for index, first in enumerate(locations):
            for second in locations[index + 1:]:
                if first == second or first in second.parents or second in first.parents:
                    raise PrivacyError("PrivacyGuard directories must not overlap")
        self.lock = threading.RLock()
        self.processing_lock = threading.RLock()
        self.blocked = None
        state_directory.mkdir(parents=True, exist_ok=True)
        self.process_lock = FileLock(str(state_directory / "instance.lock"))
        self.process_lock.acquire(timeout=0)
        self.db = None
        try:
            self.db = sqlite3.connect(state_directory / "journal.sqlite3", check_same_thread=False)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA foreign_keys=ON")
            if self.db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise PrivacyError("Privacy journal is corrupt; automatic deletion stopped")
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2):
                raise PrivacyError("Unsupported privacy journal version")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, document TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY, task TEXT NOT NULL, kind TEXT NOT NULL,
                    path TEXT NOT NULL, version TEXT NOT NULL, document TEXT NOT NULL,
                    UNIQUE(task, kind, path, version),
                    FOREIGN KEY(task) REFERENCES tasks(id)
                );
                CREATE TABLE IF NOT EXISTS reservations (
                    id TEXT PRIMARY KEY, task TEXT NOT NULL, paths TEXT NOT NULL, uncertain INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS media (
                    kind TEXT NOT NULL, path TEXT NOT NULL, file TEXT NOT NULL,
                    version TEXT NOT NULL, size INTEGER NOT NULL, active INTEGER NOT NULL,
                    PRIMARY KEY(kind, file)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS media_current ON media(kind, path) WHERE active=1;
                PRAGMA user_version=2;
            """)
            self.db.commit()
            if self.db.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise PrivacyError("Privacy journal has orphaned file records")
            self.check_output_directory()
        except BaseException:
            if self.db is not None:
                self.db.close()
            self.process_lock.release()
            raise

    def close(self):
        self.db.close()
        self.process_lock.release()

    def check_output_directory(self):
        root = self.roots["output"]
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=root, prefix=".privacy-check-", delete=False) as stream:
            source = Path(stream.name)
        destination = source.with_name(source.name + ".published")
        try:
            publish_file(source, destination)
        finally:
            source.unlink(missing_ok=True)
            destination.unlink(missing_ok=True)

    def rows(self, statement, parameters=()):
        with self.lock:
            return self.db.execute(statement, parameters).fetchall()

    def change(self, statement, parameters=()):
        with self.lock, self.db:
            self.db.execute(statement, parameters)

    def task(self, task_id):
        rows = self.rows("SELECT document FROM tasks WHERE id=?", (task_id,))
        return json.loads(rows[0][0]) if rows else None

    def save_task(self, task_id, task):
        self.change("INSERT OR REPLACE INTO tasks VALUES (?,?)", (task_id, json.dumps(task)))

    def ready(self):
        if self.blocked:
            raise PrivacyError(self.blocked)

    def reserve(self, prompt_id, paths=(), uncertain=False, group=None):
        with self.lock:
            self.ready()
            self.change("INSERT OR REPLACE INTO reservations VALUES (?,?,?,?)", (prompt_id, group or prompt_id, json.dumps(sorted(paths)), int(uncertain)))

    def release(self, prompt_id):
        self.change("DELETE FROM reservations WHERE id=?", (prompt_id,))

    def group_for(self, prompt_id):
        rows = self.rows("SELECT task FROM reservations WHERE id=?", (prompt_id,))
        return rows[0][0] if rows else prompt_id

    def group_pending(self, group, excluding=None):
        return [row[0] for row in self.rows("SELECT id FROM reservations WHERE task=? AND id!=?", (group, excluding or ""))]

    def prepare_close(self, group):
        task = self.task(group)
        if task is not None and task["baseline"] is None:
            task["baseline"] = {kind: snapshot(self.roots[kind]) for kind in ("temp", "output")}
            task["writes"] = {"temp": [], "output": []}
            self.save_task(group, task)
            return True
        return False

    def refresh_owned(self, group):
        for row in self.rows("SELECT * FROM files WHERE task=? AND kind!='input'", (group,)):
            path = contained(self.roots[row["kind"]], self.roots[row["kind"]] / row["path"])
            if path is None:
                continue
            old = json.loads(row["version"])
            current = identity(path)
            if current is not None and current[:2] == old[:2] and current != old:
                self.record(group, row["kind"], row["path"], current)

    def capture_expected(self, group):
        task = self.task(group)
        for kind, files in task["expected"].items():
            for relative, before in files.items():
                if kind == "output" and not is_media(relative):
                    continue
                path = contained(self.roots[kind], self.roots[kind] / relative)
                if path is None:
                    raise PrivacyError("An expected encoder path became a link")
                current = identity(path)
                if current is None or current == before:
                    continue
                recorded = self.rows("SELECT version FROM files WHERE task=? AND kind=? AND path=?", (group, kind, relative))
                if recorded and not any(json.loads(row[0])[:2] == current[:2] for row in recorded):
                    continue
                self.record(group, kind, relative, current)

    def begin(self, prompt_id):
        self.ready()
        group = self.group_for(prompt_id)
        task = self.task(group)
        if task is None:
            task = {
                "roots": {kind: str(path) for kind, path in self.roots.items()},
                "prompts": [], "baseline": None, "writes": {}, "expected": {"temp": {}, "output": {}}, "directories": [], "holding": False,
                "report": {"deleted_input": 0, "deleted_temp": 0, "encrypted": [], "lost_outputs": [], "replaced": [], "errors": []},
            }
        if prompt_id not in task["prompts"]:
            task["prompts"].append(prompt_id)
        task["baseline"] = {kind: snapshot(self.roots[kind]) for kind in ("temp", "output")}
        task["writes"] = {"temp": [], "output": []}
        task["holding"] = False
        self.save_task(group, task)
        return group

    def record(self, task_id, kind, relative, version):
        identifier = uuid.uuid4().hex
        self.change("INSERT OR IGNORE INTO files VALUES (?,?,?,?,?,?)", (
            identifier, task_id, kind, relative, json.dumps(version),
            json.dumps({"stage": "pending", "partial": None, "destination": None, "digest": None}),
        ))

    def record_input(self, task_id, path):
        path = contained(self.roots["input"], path)
        if path is None or not is_image(path):
            return
        version = identity(path)
        if version is not None:
            self.record(task_id, "input", path.relative_to(self.roots["input"]).as_posix(), version)

    def record_write(self, task_id, path):
        for kind in ("temp", "output"):
            safe = contained(self.roots[kind], path)
            if safe is None:
                continue
            relative = safe.relative_to(self.roots[kind]).as_posix()
            with self.lock:
                task = self.task(task_id)
                if task is not None and task["baseline"] is not None and relative not in task["writes"][kind]:
                    task["writes"][kind].append(relative)
                    if relative not in task["expected"][kind]:
                        task["expected"][kind][relative] = identity(safe)
                    self.save_task(task_id, task)

    def capture(self, task_id):
        task = self.task(task_id)
        if task is None or task["baseline"] is None:
            return
        changes = []
        owned = {(row["kind"], row["path"]): row["task"] for row in self.rows("SELECT kind,path,task FROM files WHERE kind!='input'")}
        for kind in ("temp", "output"):
            before, old_directories = task["baseline"][kind]
            after, directories = snapshot(self.roots[kind])
            for relative, version in after.items():
                if before.get(relative) == version and relative not in task["writes"].get(kind, []):
                    continue
                if kind == "output" and not is_media(relative):
                    continue
                if owned.get((kind, relative), task_id) != task_id:
                    continue
                changes.append((kind, relative, version))
            if kind == "temp":
                task["directories"] = sorted(set(task["directories"]) | (set(directories) - set(old_directories)))
        # A captured segment and its action list must survive or roll back together.
        with self.lock:
            try:
                for kind, relative, version in changes:
                    self.db.execute("INSERT OR IGNORE INTO files VALUES (?,?,?,?,?,?)", (
                        uuid.uuid4().hex, task_id, kind, relative, json.dumps(version),
                        json.dumps({"stage": "pending", "partial": None, "destination": None, "digest": None}),
                    ))
                task["baseline"] = None
                task["writes"] = {}
                self.db.execute("UPDATE tasks SET document=? WHERE id=?", (json.dumps(task), task_id))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def end(self, prompt_id, success=True):
        group = self.group_for(prompt_id)
        self.capture(group)
        self.release(prompt_id)
        task = self.task(group)
        task["holding"] = success and bool(self.group_pending(group))
        self.save_task(group, task)
        return self.cleanup(group)

    def shared(self, relative):
        for row in self.rows("SELECT paths,uncertain FROM reservations"):
            if row["uncertain"] or relative in json.loads(row["paths"]):
                return True
        return False

    def update_file(self, row, document):
        self.change("UPDATE files SET document=? WHERE id=?", (json.dumps(document), row["id"]))

    def remember_media(self, kind, relative, encrypted, size):
        version = identity(self.artifact(encrypted, kind))
        if version is None:
            raise PrivacyError("Ciphertext disappeared before its view mapping was committed")
        with self.lock, self.db:
            self.db.execute("UPDATE media SET active=0 WHERE kind=? AND path=?", (kind, relative))
            self.db.execute("INSERT OR REPLACE INTO media VALUES (?,?,?,?,?,1)", (kind, relative, encrypted, json.dumps(version), size))

    def mapped_media(self, kind, relative):
        rows = self.rows("SELECT * FROM media WHERE kind=? AND path=? AND active=1", (kind, relative))
        if not rows:
            return None
        row = rows[0]
        path = self.artifact(row["file"], kind)
        version = identity(path)
        if version is None:
            self.change("DELETE FROM media WHERE kind=? AND file=?", (kind, row["file"]))
            return None
        if version != json.loads(row["version"]):
            raise PrivacyError("Mapped ciphertext was replaced or modified")
        return path, row["size"]

    def prune_media(self):
        for row in self.rows("SELECT kind,file FROM media"):
            if identity(self.artifact(row["file"], row["kind"])) is None:
                self.change("DELETE FROM media WHERE kind=? AND file=?", (row["kind"], row["file"]))

    def artifact(self, relative, kind="output"):
        path = contained(self.roots[kind], self.roots[kind] / relative)
        if path is None:
            raise PrivacyError("Encrypted artifact escaped its directory or became a link")
        return path

    def remove_partial(self, document, kind="output"):
        if document["partial"]:
            path = self.artifact(document["partial"], kind)
            if not path.name.startswith(".privacy-") or not path.name.endswith(".part"):
                raise PrivacyError("Invalid partial artifact in privacy journal")
            version = identity(path)
            if version is not None:
                remove_version(self.roots[kind], document["partial"], version)

    def encrypt(self, row, report):
        kind = row["kind"]
        root = self.roots[kind]
        document = json.loads(row["document"])
        version = json.loads(row["version"])
        source = self.artifact(row["path"], kind)
        if document["destination"] and (self.artifact(document["destination"], kind).parent != source.parent or not document["destination"].endswith(".cpriv")):
            raise PrivacyError("Invalid ciphertext destination in privacy journal")
        if document["partial"] and self.artifact(document["partial"], kind).parent != source.parent:
            raise PrivacyError("Invalid partial destination in privacy journal")
        if document["stage"] in ("verified", "published"):
            destination = self.artifact(document["destination"], kind)
            partial = self.artifact(document["partial"], kind)
            candidate = destination if destination.exists() else partial
            if candidate.exists() and crypto.file_digest(candidate) == document["digest"]:
                with open(candidate, "rb") as encrypted:
                    crypto.read_header(encrypted)
                if candidate == partial:
                    publish_file(partial, destination)
                self.remove_partial(document, kind)
                self.remember_media(kind, row["path"], document["destination"], version[2])
                removed = remove_version(root, row["path"], version)
                if kind == "temp" and removed == "deleted":
                    report["deleted_temp"] += 1
                report["encrypted"].append({"type": kind, "source": row["path"], "file": document["destination"]})
                return
            if kind == "temp" and not source.exists() and not candidate.exists():
                return
            if identity(source) == version:
                document["stage"] = "pending"
            else:
                raise PrivacyError("Verified ciphertext is missing or damaged; recovery stopped")
        if document["stage"] == "discard":
            self.remove_partial(document, kind)
            remove_version(root, row["path"], version)
            report["lost_outputs"].append(row["path"])
            report["errors"].append(f"Recovered a failed encryption; plaintext discarded: {row['path']}")
            return
        if identity(source) != version:
            self.remove_partial(document, kind)
            report["replaced"].append(kind + "/" + row["path"])
            return
        try:
            self.remove_partial(document, kind)
            destination = source.with_suffix(".cpriv")
            if destination.exists():
                destination = source.with_name(source.stem + "." + uuid.uuid4().hex + ".cpriv")
            partial = source.with_name(".privacy-" + uuid.uuid4().hex + ".part")
            document.update(stage="writing", destination=destination.relative_to(root).as_posix(), partial=partial.relative_to(root).as_posix(), digest=None)
            self.update_file(row, document)
            with open(source, "rb") as plain, open(partial, "xb") as encrypted:
                plain_digest = crypto.encrypt_stream(plain, encrypted, filename=source.name)
            with open(partial, "rb") as encrypted:
                verified = crypto.decrypt_stream(encrypted)
            if verified != plain_digest:
                raise PrivacyError("Encrypted file verification failed")
            if identity(source) != version:
                self.remove_partial(document, kind)
                report["replaced"].append(kind + "/" + row["path"])
                return
            document.update(stage="verified", digest=crypto.file_digest(partial))
            self.update_file(row, document)
            publish_file(partial, destination)
            document["stage"] = "published"
            self.update_file(row, document)
        except Exception as error:
            # The configured policy deliberately sacrifices an output on encryption failure.
            document["stage"] = "discard"
            self.update_file(row, document)
            remove_version(root, row["path"], version)
            self.remove_partial(document, kind)
            report["lost_outputs"].append(row["path"])
            report["errors"].append(f"Encryption failed; plaintext discarded: {row['path']} ({type(error).__name__})")
            return
        self.remember_media(kind, row["path"], document["destination"], version[2])
        removed = remove_version(root, row["path"], version)
        if kind == "temp" and removed == "deleted":
            report["deleted_temp"] += 1
        report["encrypted"].append({"type": kind, "source": row["path"], "file": document["destination"]})

    def cleanup(self, task_id):
        with self.processing_lock:
            return self._cleanup(task_id)

    def _cleanup(self, task_id):
        task = self.task(task_id)
        if task is None:
            return None
        if task["holding"]:
            return {**task["report"], "status": "pending", "prompt_ids": task["prompts"]}
        report = task["report"]
        remaining_errors = []
        for row in self.rows("SELECT * FROM files WHERE task=? ORDER BY CASE kind WHEN 'temp' THEN 0 WHEN 'output' THEN 1 ELSE 2 END", (task_id,)):
            try:
                if row["kind"] == "input":
                    with self.lock:
                        if self.shared(row["path"]):
                            continue
                        result = remove_version(self.roots["input"], row["path"], json.loads(row["version"]))
                        if result == "deleted":
                            report["deleted_input"] += 1
                        elif result == "replaced":
                            report["replaced"].append("input/" + row["path"])
                elif row["kind"] == "temp" and not is_media(row["path"]):
                    result = remove_version(self.roots["temp"], row["path"], json.loads(row["version"]))
                    if result == "deleted":
                        report["deleted_temp"] += 1
                else:
                    self.encrypt(row, report)
                with self.lock, self.db:
                    self.db.execute("DELETE FROM files WHERE id=?", (row["id"],))
                    if row["kind"] in task["expected"] and self.db.execute("SELECT 1 FROM files WHERE task=? AND kind=? AND path=?", (task_id, row["kind"], row["path"])).fetchone() is None:
                        task["expected"][row["kind"]].pop(row["path"], None)
                    self.db.execute("UPDATE tasks SET document=? WHERE id=?", (json.dumps(task), task_id))
            except Exception as error:
                remaining_errors.append(f"Unfinished {row['kind']}/{row['path']}: {type(error).__name__}: {error}")
        retry_directories = []
        pending_temp = [row[0] for row in self.rows("SELECT path FROM files WHERE task=? AND kind='temp'", (task_id,))]
        for relative in sorted(task["directories"], key=lambda value: value.count("/"), reverse=True):
            path = contained(self.roots["temp"], self.roots["temp"] / relative)
            if path is not None and path.is_dir() and not any(path.iterdir()):
                try:
                    path.rmdir()
                except OSError as error:
                    remaining_errors.append(f"Cannot remove temporary directory {relative}: {error}")
                    retry_directories.append(relative)
            elif any(name.startswith(relative + "/") for name in pending_temp):
                retry_directories.append(relative)
        task["directories"] = retry_directories
        self.save_task(task_id, task)
        pending = len(self.rows("SELECT id FROM files WHERE task=?", (task_id,)))
        status = "error" if report["errors"] or remaining_errors else ("pending" if pending else "complete")
        result = {**report, "errors": report["errors"] + remaining_errors, "status": status, "pending_files": pending, "prompt_ids": task["prompts"]}
        if remaining_errors:
            self.blocked = "Privacy cleanup is incomplete; correct the reported error and restart ComfyUI"
        elif pending == 0:
            self.change("DELETE FROM tasks WHERE id=?", (task_id,))
        return result

    def flush(self):
        results = []
        for row in self.rows("SELECT id,document FROM tasks"):
            task = json.loads(row["document"])
            if task["baseline"] is None:
                if task["holding"] and not self.group_pending(row["id"]):
                    task["holding"] = False
                    self.save_task(row["id"], task)
                results.append(self.cleanup(row["id"]))
        return [result for result in results if result is not None]

    def recover(self):
        for row in self.rows("SELECT kind,document FROM files WHERE kind!='input'"):
            document = json.loads(row["document"])
            for name in (document["partial"], document["destination"]):
                if not name:
                    continue
                path = self.artifact(name, row["kind"])
                if path.exists():
                    with open(path, "rb") as stream:
                        if stream.read(len(crypto.LEGACY_MAGIC)) == crypto.LEGACY_MAGIC:
                            raise crypto.LegacyFormatError("Unfinished PrivacyGuard v1 output: use the original v1 tool before upgrading")
        self.prune_media()
        self.change("DELETE FROM reservations")
        for row in self.rows("SELECT id,document FROM tasks"):
            task = json.loads(row["document"])
            if task["roots"] != {kind: str(path) for kind, path in self.roots.items()}:
                raise PrivacyError("Protected directories changed; restore the recorded directories before recovery")
            self.capture(row["id"])
            self.capture_expected(row["id"])
            self.refresh_owned(row["id"])
            task = self.task(row["id"])
            task["holding"] = False
            self.save_task(row["id"], task)
        results = self.flush()
        self.ready()
        return results
