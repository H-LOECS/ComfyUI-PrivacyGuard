import contextvars
from contextlib import contextmanager
import functools
import logging
import os
import sys
import threading
import weakref
from importlib.metadata import version
from pathlib import Path

from aiohttp import web

import execution
import folder_paths
import nodes

from .paths import contained, is_image, snapshot

try:
    from .guard import Guard
    from .view import ViewService, resolve_request
    DEPENDENCY_ERROR = None
except ImportError as error:
    Guard = None
    DEPENDENCY_ERROR = str(error)


class Integration:
    def __init__(self, server):
        self.server = server
        self.queue = server.prompt_queue
        self.guard = None
        self.views = None
        self.error = None
        self.enabled = True
        self.active_group = None
        self.node_context = contextvars.ContextVar("privacy_node", default=None)
        self.requeue_context = contextvars.ContextVar("privacy_requeue", default=None)
        self.audit_local = threading.local()
        self.batches = {}
        self.reports = {}
        self.patches = []
        self.middleware = None
        self.vhs_modules = set()
        try:
            self.initialize()
        except Exception as error:
            self.error = f"PrivacyGuard is not ready: {type(error).__name__}: {error}"
            logging.error(self.error)

    def initialize(self):
        if DEPENDENCY_ERROR:
            raise RuntimeError(f"Install PrivacyGuard requirements: {DEPENDENCY_ERROR}")
        if not (1, 6, 2) <= tuple(int(part) for part in version("PyNaCl").split(".")) < (2, 0):
            raise RuntimeError("PrivacyGuard requires PyNaCl >=1.6.2,<2; install its requirements with ComfyUI stopped")
        roots = {"input": folder_paths.get_input_directory(), "temp": folder_paths.get_temp_directory(), "output": folder_paths.get_output_directory()}
        self.guard = Guard(roots, Path(folder_paths.get_user_directory()) / "privacyguard")
        for report in self.guard.recover():
            self.publish(report)
        self.views = ViewService(self.guard)
        logging.info("PrivacyGuard ready; time-derived encryption")

    def ready(self):
        if self.error:
            raise RuntimeError(self.error)
        if self.guard is None:
            raise RuntimeError("PrivacyGuard has not initialized")
        current = {"input": folder_paths.get_input_directory(), "temp": folder_paths.get_temp_directory(), "output": folder_paths.get_output_directory()}
        if {kind: Path(path).resolve() for kind, path in current.items()} != self.guard.roots:
            raise RuntimeError("Protected directories changed; restart ComfyUI to reinitialize PrivacyGuard")
        self.guard.ready()

    def patch(self, owner, name, replacement):
        original = getattr(owner, name)
        self.patches.append((owner, name, original, replacement))
        setattr(owner, name, replacement)

    def uninstall(self):
        # Audit hooks cannot be removed, so deactivate this observer before restoring wrappers.
        self.enabled = False
        for owner, name, original, replacement in reversed(self.patches):
            if getattr(owner, name) is replacement:
                setattr(owner, name, original)
        if self.middleware is not None and not self.server.app.middlewares.frozen:
            self.server.app.middlewares.remove(self.middleware)
        if self.guard is not None:
            self.guard.close()

    def references(self, prompt):
        paths = set()
        uncertain = False
        root = self.guard.roots["input"]
        path_fields = {"image", "mask", "file", "filename", "directory", "folder", "path", "image_path", "video", "source"}
        for node in prompt.values():
            for name, value in node.get("inputs", {}).items():
                if isinstance(value, list) and len(value) == 2 and name in path_fields:
                    uncertain = True
                if not isinstance(value, str) or not value:
                    continue
                filename, annotation = folder_paths.annotated_filepath(value)
                if annotation is not None and Path(annotation).resolve() != root:
                    continue
                candidates = [root / filename] if not Path(filename).is_absolute() else [Path(filename)]
                if not Path(filename).is_absolute():
                    candidates.append(Path(os.path.abspath(filename)))
                for candidate in candidates:
                    candidate = contained(root, candidate)
                    if candidate is None:
                        continue
                    if candidate.is_file() and is_image(candidate):
                        paths.add(candidate.relative_to(root).as_posix())
                    elif candidate.is_dir():
                        files, _ = snapshot(candidate)
                        for relative in files:
                            if is_image(relative):
                                paths.add((candidate / relative).relative_to(root).as_posix())
        return paths, uncertain

    def record_read(self, path):
        context = self.node_context.get()
        if not self.enabled or context is None or self.guard is None or isinstance(path, int):
            return
        if getattr(self.audit_local, "busy", False):
            return
        self.audit_local.busy = True
        try:
            self.guard.record_input(context[0], os.fsdecode(path))
        finally:
            self.audit_local.busy = False

    def audit(self, event, arguments):
        if event != "open" or not self.enabled or self.node_context.get() is None:
            return
        path, mode, flags = arguments
        access = flags & (os.O_WRONLY | os.O_RDWR)
        readable = ("r" in mode or "+" in mode) if isinstance(mode, str) else access != os.O_WRONLY
        if readable:
            self.record_read(path)
        writable = any(flag in mode for flag in ("w", "a", "x", "+")) if isinstance(mode, str) else access != os.O_RDONLY
        if writable and self.guard is not None and not isinstance(path, int) and not getattr(self.audit_local, "busy", False):
            self.audit_local.busy = True
            try:
                self.guard.record_write(self.node_context.get()[0], os.fsdecode(path))
            finally:
                self.audit_local.busy = False

    def adapt_vhs(self):
        cls = nodes.NODE_CLASS_MAPPINGS.get("VHS_BatchManager")
        if cls is None:
            return
        module = sys.modules[cls.__module__]
        utilities = sys.modules[module.requeue_workflow.__module__]
        if utilities.__name__ in self.vhs_modules:
            return
        original = utilities.requeue_workflow_unchecked

        @functools.wraps(original)
        def requeue(*args, **kwargs):
            token = self.requeue_context.set(self.active_group)
            try:
                return original(*args, **kwargs)
            finally:
                self.requeue_context.reset(token)

        self.patch(utilities, "requeue_workflow_unchecked", requeue)
        original_ffmpeg = module.ffmpeg_process

        @functools.wraps(original_ffmpeg)
        def ffmpeg_process(args, video_format, video_metadata, file_path, env):
            if self.active_group is not None:
                self.guard.record_write(self.active_group, file_path)
            return original_ffmpeg(args, video_format, video_metadata, file_path, env)

        original_gifski = module.gifski_process

        @functools.wraps(original_gifski)
        def gifski_process(args, dimensions, frame_rate, video_format, file_path, env):
            if self.active_group is not None:
                self.guard.record_write(self.active_group, file_path)
            return original_gifski(args, dimensions, frame_rate, video_format, file_path, env)

        self.patch(module, "ffmpeg_process", ffmpeg_process)
        self.patch(module, "gifski_process", gifski_process)
        self.vhs_modules.add(utilities.__name__)

    def close_batches(self, group):
        if group not in self.batches:
            return
        closing = self.guard.prepare_close(group)
        for reference in self.batches.get(group, {}).values():
            manager = reference()
            if manager is not None:
                manager.reset()
        self.batches.pop(group, None)
        if closing:
            self.guard.capture(group)
        self.guard.capture_expected(group)
        self.guard.refresh_owned(group)

    def publish(self, report):
        if report is None:
            return
        for prompt_id in report["prompt_ids"]:
            with self.queue.mutex:
                if prompt_id in self.queue.history:
                    self.queue.history[prompt_id]["privacy"] = report
                elif any(item[1] == prompt_id for item in self.queue.currently_running.values()):
                    self.reports[prompt_id] = report
            self.server.send_sync("privacy_cleanup", {"prompt_id": prompt_id, "privacy": report}, self.server.client_id)
        if report["errors"]:
            for message in report["errors"]:
                logging.error("PrivacyGuard: %s", message)
        else:
            logging.info("PrivacyGuard %s: input=%d temp=%d encrypted=%d", report["status"], report["deleted_input"], report["deleted_temp"], len(report["encrypted"]))

    def flush(self):
        if self.guard is None:
            return
        try:
            for group in list(self.batches):
                if group != self.active_group and not self.guard.group_pending(group):
                    self.close_batches(group)
            for report in self.guard.flush():
                self.publish(report)
        except Exception as error:
            self.guard.blocked = f"Privacy cleanup stopped: {type(error).__name__}: {error}. Restart after correcting the error."
            logging.error(self.guard.blocked)

    def missing_files(self, entry):
        if entry is None or not entry.ui:
            return False
        for value in entry.ui["output"].values():
            if not isinstance(value, list):
                continue
            for item in value:
                if not isinstance(item, dict) or item.get("type") not in ("temp", "output") or "filename" not in item:
                    continue
                root = self.guard.roots[item["type"]]
                path = contained(root, root / item.get("subfolder", "") / item["filename"])
                if path is not None and not path.exists():
                    return True
        return False

    def cached_inputs(self, graph, node_id, visited=None):
        if self.active_group is None:
            return
        visited = set() if visited is None else visited
        if node_id in visited:
            return
        visited.add(node_id)
        node = graph.dynprompt.get_node(node_id)
        kind, inputs = node["class_type"], node["inputs"]
        if kind in ("LoadImage", "LoadImageMask", "VHS_LoadImagePath"):
            value = inputs.get("image")
            if isinstance(value, str):
                path = value.strip().strip('"') if kind == "VHS_LoadImagePath" else folder_paths.get_annotated_filepath(value)
                self.guard.record_input(self.active_group, path)
        elif kind in ("VHS_LoadImages", "VHS_LoadImagesPath"):
            directory = inputs.get("directory")
            selection = [inputs.get("skip_first_images", 0), inputs.get("select_every_nth", 1), inputs.get("image_load_cap", 0)]
            if isinstance(directory, str) and all(type(value) is int for value in selection):
                module = sys.modules[nodes.NODE_CLASS_MAPPINGS[kind].__module__]
                directory = folder_paths.get_annotated_filepath(directory) if kind == "VHS_LoadImages" else directory
                if Path(directory).is_dir():
                    selected = module.get_sorted_dir_files_from_directory(directory, selection[0], selection[1], module.FolderOfImages.IMG_EXTENSIONS)
                    if selection[2] > 0:
                        selected = selected[:selection[2]]
                    for path in selected:
                        self.guard.record_input(self.active_group, path)
        for name, value in inputs.items():
            if isinstance(value, list) and len(value) == 2 and isinstance(value[0], str) and isinstance(value[1], int):
                _, _, info = graph.get_input_info(node_id, name)
                if not info or not info.get("lazy", False):
                    self.cached_inputs(graph, value[0], visited)

    @contextmanager
    def file_cache(self, executor):
        cache = executor.caches.outputs
        original_get = cache.get
        original_local = cache.get_local

        @functools.wraps(original_get)
        async def get(node_id):
            entry = await original_get(node_id)
            return None if self.missing_files(entry) else entry

        @functools.wraps(original_local)
        def get_local(node_id):
            entry = original_local(node_id)
            return None if self.missing_files(entry) else entry

        cache.get = get
        cache.get_local = get_local
        try:
            yield
        finally:
            cache.get = original_get
            cache.get_local = original_local

    def install(self):
        if not self.enabled:
            return
        original_execute = execution.PromptExecutor.execute
        original_data = execution.get_output_data
        original_path = folder_paths.get_annotated_filepath
        original_graph_cache = execution.ExecutionList.get_cache
        original_put = self.queue.put
        original_get = self.queue.get
        original_done = self.queue.task_done
        original_delete = self.queue.delete_queue_item
        original_wipe = self.queue.wipe_queue

        @functools.wraps(original_execute)
        def execute(executor, prompt, prompt_id, *args, **kwargs):
            try:
                self.ready()
                self.adapt_vhs()
                if not self.guard.rows("SELECT id FROM reservations WHERE id=?", (prompt_id,)):
                    references, uncertain = self.references(prompt)
                    self.guard.reserve(prompt_id, references, uncertain)
                group = self.guard.begin(prompt_id)
            except Exception as error:
                self.error = f"PrivacyGuard could not start the task: {type(error).__name__}: {error}"
                executor.success = False
                executor.history_result = {"outputs": {}}
                executor.status_messages = []
                executor.add_message("execution_error", {"prompt_id": prompt_id, "node_id": None, "node_type": "PrivacyGuard", "executed": [], "exception_message": self.error, "exception_type": "PrivacyNotReady", "traceback": [], "current_inputs": [], "current_outputs": []}, broadcast=True)
                self.publish({"status": "error", "prompt_ids": [prompt_id], "deleted_input": 0, "deleted_temp": 0, "encrypted": [], "lost_outputs": [], "errors": [self.error]})
                return None
            self.active_group = group
            completed = False
            try:
                with self.file_cache(executor):
                    result = original_execute(executor, prompt, prompt_id, *args, **kwargs)
                completed = executor.success
                return result
            finally:
                try:
                    if not completed:
                        for next_id in self.guard.group_pending(group, excluding=prompt_id):
                            original_delete(lambda item, next_id=next_id: item[1] == next_id)
                            self.guard.release(next_id)
                    if not completed or not self.guard.group_pending(group, excluding=prompt_id):
                        self.close_batches(group)
                    report = self.guard.end(prompt_id, success=completed)
                    self.publish(report)
                    self.flush()
                except Exception as error:
                    self.guard.blocked = f"Privacy cleanup stopped: {type(error).__name__}: {error}. Restart after correcting the error."
                    self.publish({"status": "error", "prompt_ids": [prompt_id], "deleted_input": 0, "deleted_temp": 0, "encrypted": [], "lost_outputs": [], "errors": [self.guard.blocked]})
                finally:
                    self.active_group = None

        @functools.wraps(original_data)
        async def get_output_data(prompt_id, unique_id, obj, input_data_all, *args, **kwargs):
            if self.active_group is None:
                return await original_data(prompt_id, unique_id, obj, input_data_all, *args, **kwargs)
            token = self.node_context.set((self.active_group, unique_id))
            try:
                batch_class = nodes.NODE_CLASS_MAPPINGS.get("VHS_BatchManager")
                if batch_class is not None and isinstance(obj, batch_class):
                    self.batches.setdefault(self.active_group, {})[unique_id] = weakref.ref(obj)
                native_class = nodes.NODE_CLASS_MAPPINGS.get("VHS_LoadImagePath")
                if native_class is not None and isinstance(obj, native_class):
                    for path in input_data_all.get("image", []):
                        if isinstance(path, str):
                            self.record_read(path.strip().strip('"'))
                return await original_data(prompt_id, unique_id, obj, input_data_all, *args, **kwargs)
            finally:
                self.node_context.reset(token)

        @functools.wraps(original_path)
        def annotated_path(*args, **kwargs):
            path = original_path(*args, **kwargs)
            self.record_read(path)
            return path

        @functools.wraps(original_graph_cache)
        def graph_cache(graph, from_node_id, to_node_id):
            entry = original_graph_cache(graph, from_node_id, to_node_id)
            if entry is not None:
                self.cached_inputs(graph, from_node_id)
            return entry

        @functools.wraps(original_put)
        def put(item):
            self.ready()
            references, uncertain = self.references(item[2])
            with self.queue.mutex:
                self.guard.reserve(item[1], references, uncertain, group=self.requeue_context.get())
                try:
                    return original_put(item)
                except BaseException:
                    self.guard.release(item[1])
                    raise

        @functools.wraps(original_get)
        def get(timeout=None):
            if self.error or (self.guard is not None and self.guard.blocked):
                with self.queue.not_empty:
                    self.queue.not_empty.wait(timeout=min(timeout if timeout is not None else 1.0, 1.0))
                return None
            return original_get(timeout)

        @functools.wraps(original_done)
        def task_done(item_id, history_result, status, process_item=None):
            with self.queue.mutex:
                prompt_id = self.queue.currently_running[item_id][1]
                report = self.reports.pop(prompt_id, None)
                if report is not None:
                    history_result = {**history_result, "privacy": report}
                result = original_done(item_id, history_result, status, process_item=process_item)
            self.flush()
            return result

        @functools.wraps(original_delete)
        def delete_queue_item(predicate):
            with self.queue.mutex:
                before = {item[1] for item in self.queue.queue}
                result = original_delete(predicate)
                after = {item[1] for item in self.queue.queue}
                if self.guard is not None:
                    for prompt_id in before - after:
                        self.guard.release(prompt_id)
            self.flush()
            return result

        @functools.wraps(original_wipe)
        def wipe_queue():
            with self.queue.mutex:
                before = [item[1] for item in self.queue.queue]
                result = original_wipe()
                if self.guard is not None:
                    for prompt_id in before:
                        self.guard.release(prompt_id)
            self.flush()
            return result

        @web.middleware
        async def privacy_ready(request, handler):
            if request.method in ("GET", "HEAD") and request.path.rstrip("/") in ("/view", "/api/view") and self.views is not None:
                target = resolve_request(request.query, self.guard.roots)
                if target is not None:
                    return await self.views.handle(request, *target)
            if request.method == "POST" and request.path.rstrip("/") in ("/prompt", "/api/prompt"):
                try:
                    self.ready()
                except RuntimeError as error:
                    return web.json_response({"error": {"type": "privacy_not_ready", "message": str(error), "details": "Resolve the reported error and restart ComfyUI", "extra_info": {}}, "node_errors": {}}, status=503)
            return await handler(request)

        self.patch(execution.PromptExecutor, "execute", execute)
        self.patch(execution, "get_output_data", get_output_data)
        self.patch(folder_paths, "get_annotated_filepath", annotated_path)
        self.patch(execution.ExecutionList, "get_cache", graph_cache)
        for name, method in (("put", put), ("get", get), ("task_done", task_done), ("delete_queue_item", delete_queue_item), ("wipe_queue", wipe_queue)):
            self.patch(self.queue, name, method)
        self.server.app.middlewares.append(privacy_ready)
        self.middleware = privacy_ready
        sys.addaudithook(self.audit)


def install(server):
    integration = Integration(server)
    integration.install()
    return integration
