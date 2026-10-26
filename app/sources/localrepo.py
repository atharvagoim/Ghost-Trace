"""Read a zipped local git repository entirely in memory: working-tree files plus commit history from its .git folder.

Nothing is written to disk. The zip arrives as bytes, files are read straight out of the archive, and git objects
(loose and packed) are parsed with dulwich from in-memory buffers. When the scan ends the bytes are dropped.
"""

from __future__ import annotations

import heapq
import io
import stat
import time
import zipfile
from dataclasses import dataclass, field
from typing import Iterator

from dulwich.object_format import SHA1
from dulwich.objects import Commit, ShaFile, Tree
from dulwich.pack import Pack, PackData, load_pack_index_file

from ..detection.engine import MAX_FILE_BYTES, looks_binary, should_skip_path

MAX_ENTRIES = 50_000
MAX_SCANNED_BYTES = 300 * 1024 * 1024  # uncompressed bytes we are willing to read (zip-bomb guard)
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")


class LocalRepoError(ValueError):
    pass


@dataclass
class ChangedFile:
    path: str
    old_sha: bytes | None
    new_sha: bytes


@dataclass
class HistoryCommit:
    sha: str
    time: int
    summary: str
    changes: list[ChangedFile] = field(default_factory=list)


def _norm(name: str) -> str:
    return name.replace("\\", "/")


def open_zip(data: bytes) -> zipfile.ZipFile:
    if not data.startswith(ZIP_MAGIC):
        raise LocalRepoError("That file is not a .zip archive.")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise LocalRepoError(f"The zip could not be read: {exc}") from exc
    if len(zf.infolist()) > MAX_ENTRIES:
        raise LocalRepoError(f"The zip has more than {MAX_ENTRIES:,} entries. Remove node_modules or build folders and try again.")
    return zf


def find_repo_root(names: list[str]) -> str | None:
    """Folder prefix (e.g. 'my-app/' or '') of the outermost repository in the zip, or None if there is no .git."""
    roots = [n[: -len(".git/HEAD")] for n in names if n == ".git/HEAD" or n.endswith("/.git/HEAD")]
    roots = [r for r in roots if "node_modules/" not in r]
    return min(roots, key=lambda r: r.count("/")) if roots else None


def common_prefix(names: list[str]) -> str:
    """'project/' when every entry sits inside one top-level folder (how most zip tools package a folder)."""
    tops = {n.split("/", 1)[0] for n in names if n}
    if len(tops) == 1 and all("/" in n or n.endswith("/") for n in names if n):
        return next(iter(tops)) + "/"
    return ""


class ZipGit:
    """Just enough of a git object database, backed by entries of an in-memory zip."""

    def __init__(self, zf: zipfile.ZipFile, git_dir: str):
        self.zf = zf
        self.git_dir = git_dir  # e.g. 'my-app/.git/'
        names = [_norm(i.filename) for i in zf.infolist()]
        self._name_map = {_norm(i.filename): i for i in zf.infolist()}
        obj_prefix = git_dir + "objects/"
        self.loose: dict[bytes, zipfile.ZipInfo] = {}
        self.packs: list[Pack] = []
        for n in names:
            if not n.startswith(obj_prefix):
                continue
            rest = n[len(obj_prefix):]
            parts = rest.split("/")
            if len(parts) == 2 and len(parts[0]) == 2 and len(parts[1]) == 38:
                self.loose[(parts[0] + parts[1]).encode()] = self._name_map[n]
            elif rest.startswith("pack/") and rest.endswith(".pack"):
                idx_name = n[:-5] + ".idx"
                if idx_name in self._name_map:
                    pack_bytes = zf.read(self._name_map[n])
                    idx_bytes = zf.read(self._name_map[idx_name])
                    data = PackData(n, object_format=SHA1, file=io.BytesIO(pack_bytes), size=len(pack_bytes))
                    idx = load_pack_index_file(idx_name, io.BytesIO(idx_bytes), SHA1)
                    self.packs.append(Pack.from_objects(data, idx))
        self._tree_cache: dict[bytes, list[tuple[bytes, int, bytes]]] = {}

    def _read(self, rel: str) -> bytes | None:
        info = self._name_map.get(self.git_dir + rel)
        return self.zf.read(info) if info else None

    def get(self, sha: bytes) -> ShaFile:
        info = self.loose.get(sha)
        if info is not None:
            return ShaFile.from_file(io.BytesIO(self.zf.read(info)))
        for p in self.packs:
            if sha in p:
                return p[sha]
        raise KeyError(sha)

    def refs(self) -> dict[str, bytes]:
        refs: dict[str, bytes] = {}
        packed = self._read("packed-refs")
        if packed:
            for line in packed.decode("utf-8", "replace").splitlines():
                if line and not line.startswith(("#", "^")):
                    sha, _, name = line.partition(" ")
                    if len(sha) == 40:
                        refs[name.strip()] = sha.encode()
        for name, info in self._name_map.items():
            if name.startswith(self.git_dir + "refs/") and not info.is_dir():
                value = self.zf.read(info).strip()
                if len(value) == 40:
                    refs[name[len(self.git_dir):]] = value
        head = (self._read("HEAD") or b"").strip()
        if head.startswith(b"ref: "):
            target = head[5:].decode()
            if target in refs:
                refs["HEAD"] = refs[target]
        elif len(head) == 40:
            refs["HEAD"] = head
        return refs

    def head_tree_paths(self) -> set[str] | None:
        head = self.refs().get("HEAD")
        if not head:
            return None
        try:
            commit = self.get(head)
        except KeyError:
            return None
        paths: set[str] = set()
        self._walk_tree(commit.tree, "", paths)
        return paths

    def _entries(self, tree_sha: bytes) -> list[tuple[bytes, int, bytes]]:
        cached = self._tree_cache.get(tree_sha)
        if cached is None:
            tree = self.get(tree_sha)
            cached = [(e.path, e.mode, e.sha) for e in tree.items()] if isinstance(tree, Tree) else []
            if len(self._tree_cache) < 20_000:
                self._tree_cache[tree_sha] = cached
        return cached

    def _walk_tree(self, tree_sha: bytes, prefix: str, out: set[str]) -> None:
        for name, mode, sha in self._entries(tree_sha):
            path = prefix + name.decode("utf-8", "replace")
            if stat.S_ISDIR(mode):
                self._walk_tree(sha, path + "/", out)
            elif not stat.S_ISLNK(mode) and mode != 0o160000:
                out.add(path)

    def _diff(self, old: bytes | None, new: bytes, prefix: str, out: list[ChangedFile]) -> None:
        """Files added or modified between two trees. Unchanged subtrees (same id) are skipped without reading."""
        if old == new:
            return
        old_entries = {n: (m, s) for n, m, s in self._entries(old)} if old else {}
        for name, mode, sha in self._entries(new):
            path = prefix + name.decode("utf-8", "replace")
            prev = old_entries.get(name)
            if stat.S_ISDIR(mode):
                self._diff(prev[1] if prev and stat.S_ISDIR(prev[0]) else None, sha, path + "/", out)
            elif mode == 0o160000 or stat.S_ISLNK(mode):
                continue  # submodules and symlinks hold no content of their own
            elif prev is None or prev[1] != sha:
                out.append(ChangedFile(path, prev[1] if prev and not stat.S_ISDIR(prev[0]) else None, sha))

    def history(self, max_commits: int, deadline: float | None = None) -> Iterator[HistoryCommit]:
        """Commits reachable from every branch and tag, newest first, each with the files it added or changed."""
        heads = {sha for name, sha in self.refs().items() if name == "HEAD" or name.startswith(("refs/heads/", "refs/remotes/", "refs/tags/"))}
        heap: list[tuple[int, bytes]] = []
        seen: set[bytes] = set()
        for sha in heads:
            try:
                obj = self.get(sha)
            except KeyError:
                continue
            if isinstance(obj, Commit):
                heapq.heappush(heap, (-obj.commit_time, sha))
                seen.add(sha)
        count = 0
        while heap and count < max_commits:
            if deadline is not None and time.monotonic() >= deadline:
                return
            _, sha = heapq.heappop(heap)
            try:
                commit = self.get(sha)
            except KeyError:
                continue  # shallow clone: parent objects are missing
            parent_tree = None
            if commit.parents:
                try:
                    parent_tree = self.get(commit.parents[0]).tree
                except KeyError:
                    parent_tree = None
            changes: list[ChangedFile] = []
            self._diff(parent_tree, commit.tree, "", changes)
            count += 1
            yield HistoryCommit(sha.decode(), commit.commit_time, commit.message.decode("utf-8", "replace").split("\n", 1)[0][:120], changes)
            for p in commit.parents:
                if p not in seen:
                    seen.add(p)
                    try:
                        heapq.heappush(heap, (-self.get(p).commit_time, p))
                    except KeyError:
                        pass

    def blob(self, sha: bytes) -> bytes | None:
        try:
            obj = self.get(sha)
        except KeyError:
            return None
        data = obj.as_raw_string()
        return data if len(data) <= MAX_FILE_BYTES else None


def working_tree(zf: zipfile.ZipFile, root: str) -> Iterator[tuple[str, bytes]]:
    """(path relative to the repo root, content) for every scannable file; .git internals and junk are skipped."""
    budget = MAX_SCANNED_BYTES
    for info in zf.infolist():
        name = _norm(info.filename)
        if info.is_dir() or not name.startswith(root):
            continue
        rel = name[len(root):]
        if not rel or rel.startswith(".git/") or "/.git/" in rel or should_skip_path(rel) or info.file_size > MAX_FILE_BYTES:
            continue
        budget -= info.file_size
        if budget < 0:
            raise LocalRepoError("The zip unpacks to more than 300 MB of source files.")
        data = zf.read(info)
        if not looks_binary(data):
            yield rel, data
