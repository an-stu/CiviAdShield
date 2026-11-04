#!/usr/bin/env python3
"""Debounced, source-only GitHub sync for the CiviAdShield project."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import logging
import os
import random
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator, Sequence
from urllib.parse import urlsplit


PROJECT_ROOT = Path("/Users/an/Public/Codes/test/CiviAdShield")
EXPECTED_HTTPS_ORIGIN = "https://github.com/an-stu/CiviAdShield.git"
EXPECTED_SSH_ORIGIN = "git@github.com:an-stu/CiviAdShield.git"
BRANCH = "main"
COMMIT_MESSAGE = "chore: sync local source changes"
POLL_SECONDS = 2.0
DEBOUNCE_SECONDS = 8.0
NETWORK_RETRY_MIN_SECONDS = 30.0
NETWORK_RETRY_MAX_SECONDS = 60.0

ALLOWED_EXTENSIONS = frozenset({
    ".java", ".kt", ".xml", ".gradle", ".properties", ".py", ".sh",
    ".yml", ".yaml", ".md", ".txt", ".bat",
})
ALLOWED_ROOT_FILES = frozenset({
    "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "PERMISSIONS.md",
    "VALIDATION.md", "SETUP-NOTES.txt", ".gitignore", "settings.gradle",
    "build.gradle", "gradle.properties", "gradlew", "gradlew.bat",
})
SOURCE_ROOTS = frozenset({"app", "test-fixture", "gradle/wrapper", "tools", ".github", "tests"})
EXCLUDED_PARTS = frozenset({".git", ".gradle", ".toolchain", ".signing", "dist", "build"})
SECRET_EXTENSIONS = frozenset({
    ".key", ".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".jks", ".keystore",
})
PRIVATE_KEY_PATTERN = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
GITHUB_TOKEN_PATTERN = re.compile(rb"(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{20,}")


class SyncError(Exception):
    """A safe-to-log sync failure; details never include command output or URLs."""


class NetworkFailure(SyncError):
    pass


class GitFailure(SyncError):
    def __init__(self, operation: str, code: int):
        super().__init__(f"git {operation} failed (exit {code})")
        self.operation = operation
        self.code = code


class UnsafeContent(SyncError):
    pass


@dataclass(frozen=True)
class SyncResult:
    status: str
    staged_count: int = 0


def _path_bytes(values: bytes) -> list[bytes]:
    return [item for item in values.split(b"\0") if item]


def is_approved_github_origin(url: str) -> bool:
    """Accept only the owner's HTTPS or standard GitHub SSH remote URL."""
    if url in {EXPECTED_HTTPS_ORIGIN, EXPECTED_HTTPS_ORIGIN.removesuffix(".git"),
               EXPECTED_SSH_ORIGIN, EXPECTED_SSH_ORIGIN.removesuffix(".git")}:
        return True
    if url.startswith("https://"):
        try:
            parsed = urlsplit(url)
            return (
                parsed.scheme == "https"
                and parsed.netloc == "github.com"
                and parsed.path in {"/an-stu/CiviAdShield", "/an-stu/CiviAdShield.git"}
                and not parsed.query
                and not parsed.fragment
                and parsed.username is None
                and parsed.password is None
                and parsed.port is None
            )
        except ValueError:
            return False
    if url.startswith("ssh://"):
        try:
            parsed = urlsplit(url)
            return (
                parsed.scheme == "ssh"
                and parsed.netloc == "git@github.com"
                and parsed.path in {"/an-stu/CiviAdShield", "/an-stu/CiviAdShield.git"}
                and not parsed.query
                and not parsed.fragment
                and parsed.username == "git"
                and parsed.password is None
                and parsed.port is None
            )
        except ValueError:
            return False
    return False


def is_candidate_path(relative: str, tracked: bool) -> bool:
    """Return whether a repository-relative path is in the source-only allowlist."""
    if not relative or relative.startswith("/") or "\\" in relative:
        return False
    path = PurePosixPath(relative)
    parts = path.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return False
    if any(part in EXCLUDED_PARTS for part in parts):
        return False
    name = parts[-1].lower()
    name_tokens = set(re.split(r"[^a-z0-9]+", name))
    compact_name = re.sub(r"[^a-z0-9]", "", name)
    secret_tokens = {"key", "keys", "cert", "certificate", "certificates", "pem", "jks",
                     "keystore", "credential", "credentials", "secret", "secrets",
                     "token", "tokens", "signing"}
    if name == "local.properties" or name == ".env" or name.startswith(".env.") \
            or name.endswith(".env") or name_tokens & secret_tokens \
            or "keystore" in compact_name or "privatekey" in compact_name:
        return False
    if Path(name).suffix in SECRET_EXTENSIONS:
        return False
    if relative == "app/src/main/assets/filters/adguard-dns-meta.json":
        return True
    if relative == "gradle/wrapper/gradle-wrapper.jar":
        return tracked
    if len(parts) == 1 and relative in ALLOWED_ROOT_FILES:
        if relative == "SETUP-NOTES.txt" and not tracked:
            return False
        return True
    if path.suffix.lower() == ".md" and (
            (len(parts) == 2 and parts[0] == "docs")
            or (len(parts) == 3 and parts[:2] == ("docs", "releases"))):
        return True
    in_source_root = any(relative.startswith(root + "/") for root in SOURCE_ROOTS)
    if not in_source_root:
        return False
    return path.suffix.lower() in ALLOWED_EXTENSIONS


def contains_private_material(content: bytes) -> bool:
    return bool(PRIVATE_KEY_PATTERN.search(content) or GITHUB_TOKEN_PATTERN.search(content))


def is_text_content(content: bytes, allow_wrapper_jar: bool = False) -> bool:
    if allow_wrapper_jar:
        return not contains_private_material(content)
    if b"\0" in content:
        return False
    try:
        content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    return not contains_private_material(content)


class LiveSync:
    def __init__(
        self,
        repo_root: Path = PROJECT_ROOT,
        *,
        test_origin: str | None = None,
        debounce_seconds: float = DEBOUNCE_SECONDS,
        poll_seconds: float = POLL_SECONDS,
        sleep=time.sleep,
        monotonic=time.monotonic,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.test_origin = test_origin
        self.debounce_seconds = debounce_seconds
        self.poll_seconds = poll_seconds
        self._sleep = sleep
        self._monotonic = monotonic
        self._verified = False

    def _git(self, args: Sequence[str], *, check: bool = True, input_bytes: bytes | None = None,
             allowed_codes: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[bytes]:
        try:
            env = os.environ.copy()
            env["GIT_TERMINAL_PROMPT"] = "0"
            timeout = 45.0 if args and args[0] in {"fetch", "push"} else None
            result = subprocess.run(
                ["git", *args], cwd=self.repo_root, input=input_bytes,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            operation = args[0] if args else "command"
            if operation in {"fetch", "push"}:
                raise NetworkFailure("git network operation timed out") from exc
            raise GitFailure(operation, 124) from exc
        except OSError as exc:
            raise SyncError("git executable is unavailable") from exc
        if check and result.returncode not in allowed_codes:
            operation = args[0] if args else "command"
            raise GitFailure(operation, result.returncode)
        return result

    def _git_text(self, args: Sequence[str], *, check: bool = True,
                  allowed_codes: tuple[int, ...] = (0,)) -> str:
        result = self._git(args, check=check, allowed_codes=allowed_codes)
        return result.stdout.decode("utf-8", "replace").strip()

    def validate_repository(self) -> None:
        if not self.repo_root.is_dir():
            raise SyncError("project root is unavailable")
        if self.test_origin is None:
            if self.repo_root != PROJECT_ROOT.resolve():
                raise SyncError("repository scope does not match the configured project")
        elif self.repo_root == PROJECT_ROOT.resolve():
            raise SyncError("test origin mode is not permitted for the production project")

        top = self._git_text(["rev-parse", "--show-toplevel"])
        if Path(top).resolve() != self.repo_root:
            raise SyncError("git top-level does not match the configured project root")
        branch = self._git_text(["branch", "--show-current"])
        if branch != BRANCH:
            raise SyncError("current branch is not main")
        try:
            self._git_text(["rev-parse", "--verify", "HEAD"])
        except GitFailure as exc:
            raise SyncError("repository has no main commit yet") from exc

        fetch_urls = self._git_text(["remote", "get-url", "--all", "origin"], check=False)
        push_urls = self._git_text(["remote", "get-url", "--push", "--all", "origin"], check=False)
        fetch_values = [line for line in fetch_urls.splitlines() if line]
        push_values = [line for line in push_urls.splitlines() if line]
        if not fetch_values or not push_values:
            raise SyncError("origin remote is not configured")
        if self.test_origin is not None:
            allowed = lambda value: value == self.test_origin
        else:
            allowed = is_approved_github_origin
        if not all(allowed(value) for value in fetch_values + push_values):
            raise SyncError("origin remote is outside the approved repository scope")
        self._verified = True

    def _git_state_locked(self) -> bool:
        unmerged = self._git(["ls-files", "-u", "-z"], check=True).stdout
        if unmerged:
            return True
        git_paths = ["MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD",
                     "rebase-merge", "rebase-apply", "sequencer"]
        for item in git_paths:
            raw = self._git_text(["rev-parse", "--git-path", item], check=False)
            if raw:
                candidate = Path(raw)
                if not candidate.is_absolute():
                    candidate = self.repo_root / candidate
                if candidate.exists():
                    return True
        return False

    def _staged_paths(self) -> list[bytes]:
        return _path_bytes(self._git(["diff", "--cached", "--name-only", "-z", "--no-renames"]).stdout)

    def _all_status_bytes(self) -> bytes:
        return self._git(["status", "--porcelain=v1", "-z", "--untracked-files=all"]).stdout

    def _tracked_paths(self) -> set[bytes]:
        return set(_path_bytes(self._git(["ls-files", "--cached", "-z"]).stdout))

    def _untracked_paths(self) -> set[bytes]:
        return set(_path_bytes(self._git(["ls-files", "--others", "--exclude-standard", "-z"]).stdout))

    def candidate_paths(self) -> list[bytes]:
        tracked = self._tracked_paths()
        all_paths = tracked | self._untracked_paths()
        output: list[bytes] = []
        for raw in all_paths:
            relative = os.fsdecode(raw)
            if not is_candidate_path(relative, raw in tracked):
                continue
            absolute = self.repo_root / Path(relative)
            if self._contains_symlink_component(absolute):
                continue
            output.append(raw)
        return sorted(output)

    def _contains_symlink_component(self, path: Path) -> bool:
        try:
            relative = path.relative_to(self.repo_root)
        except ValueError:
            return True
        cursor = self.repo_root
        for part in relative.parts:
            cursor = cursor / part
            try:
                if cursor.is_symlink():
                    return True
            except OSError:
                return True
        return False

    def changed_candidate_paths(self) -> list[bytes]:
        if self._staged_paths():
            return []
        tracked_changes = _path_bytes(self._git([
            "diff", "--name-only", "--no-renames", "-z", "HEAD", "--",
        ]).stdout)
        untracked = list(self._untracked_paths())
        tracked = self._tracked_paths()
        changed: set[bytes] = set()
        for raw in tracked_changes + untracked:
            if is_candidate_path(os.fsdecode(raw), raw in tracked):
                absolute = self.repo_root / Path(os.fsdecode(raw))
                if not self._contains_symlink_component(absolute):
                    changed.add(raw)
        return sorted(changed)

    def _signature(self, paths: Sequence[bytes]) -> tuple[tuple[bytes, int | None, int | None], ...]:
        values = []
        for raw in paths:
            path = self.repo_root / Path(os.fsdecode(raw))
            try:
                info = path.stat(follow_symlinks=False)
                values.append((raw, info.st_size, info.st_mtime_ns))
            except FileNotFoundError:
                values.append((raw, None, None))
            except OSError:
                values.append((raw, -1, -1))
        return tuple(values)

    def candidate_snapshot(self) -> tuple[tuple[bytes, int | None, int | None], ...] | None:
        if self._staged_paths() or self._git_state_locked():
            return None
        return self._signature(self.changed_candidate_paths())

    def _safe_worktree_files(self, paths: Sequence[bytes]) -> None:
        tracked = self._tracked_paths()
        wrapper = b"gradle/wrapper/gradle-wrapper.jar"
        for raw in paths:
            path = self.repo_root / Path(os.fsdecode(raw))
            if not path.exists():
                continue  # A tracked source deletion is safe to stage.
            if self._contains_symlink_component(path):
                raise UnsafeContent("candidate source path contains a symlink")
            try:
                content = path.read_bytes()
            except OSError as exc:
                raise UnsafeContent("candidate source file cannot be read") from exc
            allow_binary = raw == wrapper and raw in tracked
            if not is_text_content(content, allow_wrapper_jar=allow_binary):
                raise UnsafeContent("candidate source contains binary or private material")

    def _fetch_origin_main(self) -> str:
        result = self._git([
            "fetch", "--no-tags", "origin", "main:refs/remotes/origin/main",
        ], check=False)
        if result.returncode != 0:
            raise NetworkFailure("fetch origin main failed")
        try:
            return self._git_text(["rev-parse", "--verify", "refs/remotes/origin/main"])
        except GitFailure as exc:
            raise NetworkFailure("origin main is unavailable") from exc

    def _is_ancestor(self, older: str, newer: str) -> bool:
        result = self._git(["merge-base", "--is-ancestor", older, newer], check=False)
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        raise GitFailure("merge-base", result.returncode)

    def _head(self) -> str:
        return self._git_text(["rev-parse", "HEAD"])

    def _sync_commits_only(self, base: str, head: str) -> bool:
        output = self._git_text(["log", "--format=%s", "--no-merges", f"{base}..{head}"], check=False)
        if not output:
            return False
        subjects = output.splitlines()
        return all(subject == COMMIT_MESSAGE for subject in subjects)

    def _has_pending_local_sync(self) -> bool:
        result = self._git(["rev-parse", "--verify", "refs/remotes/origin/main"], check=False)
        if result.returncode != 0:
            return False
        remote_head = result.stdout.decode("ascii", "replace").strip()
        head = self._head()
        return head != remote_head and self._is_ancestor(remote_head, head) \
            and self._sync_commits_only(remote_head, head)

    def _fast_forward_if_clean(self, head: str, remote_head: str) -> str:
        if head == remote_head:
            return "aligned"
        if self._is_ancestor(head, remote_head):
            if self._all_status_bytes():
                return "needs_manual_merge"
            result = self._git(["merge", "--ff-only", remote_head], check=False)
            if result.returncode != 0:
                return "needs_manual_merge"
            return "fast_forwarded"
        if self._is_ancestor(remote_head, head):
            if self._sync_commits_only(remote_head, head):
                return "local_sync_ahead"
            return "needs_manual_merge"
        return "needs_manual_merge"

    def _index_content_is_safe(self, expected_paths: set[bytes]) -> None:
        entries = _path_bytes(self._git(["ls-files", "--stage", "-z"]).stdout)
        found: set[bytes] = set()
        for entry in entries:
            metadata, raw_path = entry.split(b"\t", 1)
            mode, object_id, stage = metadata.split(b" ", 2)
            if raw_path not in expected_paths:
                continue
            if stage != b"0" or mode == b"120000":
                raise UnsafeContent("staged source path is not a regular file")
            content = self._git(["cat-file", "blob", object_id.decode("ascii")]).stdout
            allow_binary = raw_path == b"gradle/wrapper/gradle-wrapper.jar"
            if not is_text_content(content, allow_wrapper_jar=allow_binary):
                raise UnsafeContent("staged source contains binary or private material")
            found.add(raw_path)
        for deleted_path in expected_paths - found:
            worktree_path = self.repo_root / Path(os.fsdecode(deleted_path))
            if worktree_path.exists() or worktree_path.is_symlink():
                raise UnsafeContent("staged source index changed during sync")

    def _stage_commit(self, paths: Sequence[bytes]) -> int:
        if not paths:
            return 0
        before = self._signature(paths)
        self._safe_worktree_files(paths)
        for raw in paths:
            path = os.fsdecode(raw)
            result = self._git(["--literal-pathspecs", "add", "--all", "--", path], check=False)
            if result.returncode != 0:
                raise GitFailure("add", result.returncode)
        staged = self._staged_paths()
        if not staged:
            return 0
        staged_set = set(staged)
        if not staged_set.issubset(set(paths)):
            raise SyncError("another staged path appeared; leaving the index untouched")
        if self._signature(paths) != before:
            raise SyncError("a source file changed while staging; leaving changes uncommitted")
        if self._git(["diff", "--quiet", "--", *[os.fsdecode(item) for item in paths]],
                     check=False).returncode != 0:
            raise SyncError("a source file changed while staging; leaving changes uncommitted")
        self._index_content_is_safe(staged_set)
        result = self._git(["commit", "-m", COMMIT_MESSAGE], check=False)
        if result.returncode != 0:
            raise GitFailure("commit", result.returncode)
        return len(staged_set)

    def sync_once(self, *, dry_run: bool = False) -> SyncResult:
        self.validate_repository()
        if self._git_state_locked():
            return SyncResult("merge_in_progress")
        if self._staged_paths():
            return SyncResult("staged_changes_present")

        paths = self.changed_candidate_paths()
        try:
            if paths:
                self._safe_worktree_files(paths)
        except UnsafeContent:
            return SyncResult("blocked_unsafe_content")
        if dry_run:
            return SyncResult("dry_run", len(paths))

        remote_head = self._fetch_origin_main()
        head = self._head()
        relation = self._fast_forward_if_clean(head, remote_head)
        if relation == "fast_forwarded":
            return SyncResult("fast_forwarded")
        if relation == "needs_manual_merge":
            return SyncResult("needs_manual_merge")
        if relation == "aligned" and not paths:
            return SyncResult("no_changes")
        if relation == "local_sync_ahead" and not paths:
            # A previous push may have failed after the local sync commit succeeded.
            before_push = self._fetch_origin_main()
            head = self._head()
            if not self._is_ancestor(before_push, head):
                return SyncResult("needs_manual_merge")
            pushed = self._git(["push", "origin", "main:main"], check=False)
            if pushed.returncode != 0:
                raise NetworkFailure("push origin main failed")
            return SyncResult("pushed_pending_sync")

        staged_count = self._stage_commit(paths)
        if staged_count == 0:
            if relation == "local_sync_ahead":
                return SyncResult("no_changes")
            return SyncResult("no_changes")

        head = self._head()
        before_push = self._fetch_origin_main()
        if not self._is_ancestor(before_push, head):
            return SyncResult("needs_manual_merge", staged_count)
        pushed = self._git(["push", "origin", "main:main"], check=False)
        if pushed.returncode != 0:
            raise NetworkFailure("push origin main failed")
        return SyncResult("synced", staged_count)

    def wait_for_stability(self) -> None:
        snapshot = self.candidate_snapshot()
        if snapshot is None or not snapshot:
            return
        stable_since = self._monotonic()
        while True:
            self._sleep(self.poll_seconds)
            current = self.candidate_snapshot()
            now = self._monotonic()
            if current is None:
                return
            if current != snapshot:
                snapshot = current
                stable_since = now
            elif now - stable_since >= self.debounce_seconds:
                return

    def _lock_path(self) -> Path:
        raw = self._git_text(["rev-parse", "--git-path", "civi-live-sync.lock"])
        path = Path(raw)
        return path if path.is_absolute() else self.repo_root / path

    @contextlib.contextmanager
    def lock(self) -> Iterator[bool]:
        path = self._lock_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        acquired = False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                yield False
                return
            yield True
        finally:
            if acquired:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def status_lines(self) -> list[str]:
        try:
            self.validate_repository()
            branch = self._git_text(["branch", "--show-current"])
            staged = bool(self._staged_paths())
            merge = self._git_state_locked()
            candidate_count = len(self.changed_candidate_paths())
            with self.lock() as acquired:
                lock_state = "idle" if acquired else "active"
            return [
                f"project root: {self.repo_root}",
                "repository: valid",
                f"branch: {branch}",
                "origin: approved",
                f"staged changes: {'yes' if staged else 'no'}",
                f"merge/rebase in progress: {'yes' if merge else 'no'}",
                f"candidate source changes: {candidate_count}",
                f"sync lock: {lock_state}",
            ]
        except SyncError:
            return [f"project root: {self.repo_root}", "repository: not ready"]

    def run_forever(self) -> None:
        self.validate_repository()
        logger = logging.getLogger("civi-live-sync")
        last_snapshot = self.candidate_snapshot()
        now = self._monotonic()
        dirty_since = now if last_snapshot or self._has_pending_local_sync() else None
        retry_at: float | None = None
        blocked_snapshot: tuple[tuple[bytes, int | None, int | None], ...] | None = None
        logger.info("source sync daemon started; poll=%ss debounce=%ss", self.poll_seconds,
                    self.debounce_seconds)
        while True:
            now = self._monotonic()
            snapshot = self.candidate_snapshot()
            pending_local_sync = self._has_pending_local_sync() if snapshot is not None else False
            if snapshot is None:
                if last_snapshot is not None:
                    logger.info("sync paused while staged changes or merge state is present")
                last_snapshot = None
                dirty_since = None
            elif snapshot != last_snapshot:
                last_snapshot = snapshot
                dirty_since = now if snapshot or pending_local_sync else None
                blocked_snapshot = None
                if retry_at is not None and dirty_since is not None:
                    retry_at = max(retry_at, dirty_since + self.debounce_seconds)
            elif (snapshot or pending_local_sync) and dirty_since is None \
                    and snapshot != blocked_snapshot:
                dirty_since = now

            is_stable = snapshot is not None and dirty_since is not None \
                and (snapshot or pending_local_sync) and snapshot != blocked_snapshot \
                and now - dirty_since >= self.debounce_seconds
            should_retry = retry_at is not None and now >= retry_at \
                and snapshot is not None and (not snapshot or is_stable)
            if (is_stable or should_retry) and (retry_at is None or should_retry):
                try:
                    with self.lock() as acquired:
                        if acquired:
                            result = self.sync_once()
                        else:
                            result = SyncResult("another_sync_is_running")
                    if result.status not in {"no_changes", "another_sync_is_running"}:
                        logger.info("sync result: %s", result.status)
                    retry_at = None
                    last_snapshot = self.candidate_snapshot()
                    dirty_since = None
                    if result.status in {"needs_manual_merge", "blocked_unsafe_content",
                                         "staged_changes_present", "merge_in_progress"}:
                        blocked_snapshot = last_snapshot
                except NetworkFailure:
                    delay = random.uniform(NETWORK_RETRY_MIN_SECONDS, NETWORK_RETRY_MAX_SECONDS)
                    retry_at = self._monotonic() + delay
                    logger.warning("network sync failed; retrying in %.0f seconds", delay)
                    last_snapshot = self.candidate_snapshot()
                    dirty_since = self._monotonic() if last_snapshot else None
                except SyncError as exc:
                    logger.warning("sync skipped: %s", str(exc))
                    last_snapshot = self.candidate_snapshot()
                    dirty_since = None
                    blocked_snapshot = last_snapshot
            self._sleep(self.poll_seconds)


def _configure_logging(root: Path) -> None:
    log_dir = root / ".toolchain" / "sync"
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="run one sync pass and exit")
    parser.add_argument("--dry-run", action="store_true", help="show eligible changes without staging")
    parser.add_argument("--status", action="store_true", help="show repository and sync facts")
    parser.add_argument("--test-mode", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--repo-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--test-origin", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.test_mode:
        if not args.repo_root or not args.test_origin or not args.once:
            parser.error("test mode requires --repo-root, --test-origin, and --once")
    elif args.repo_root is not None or args.test_origin is not None:
        parser.error("--repo-root and --test-origin require explicit --test-mode")
    if args.dry_run and not args.once:
        parser.error("--dry-run requires --once")
    if args.status and (args.once or args.dry_run):
        parser.error("--status cannot be combined with --once or --dry-run")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    root = args.repo_root if args.test_mode else PROJECT_ROOT
    sync = LiveSync(root, test_origin=args.test_origin if args.test_mode else None)
    if args.status:
        for line in sync.status_lines():
            print(line)
        return 0
    if args.test_mode and sync.repo_root == PROJECT_ROOT.resolve():
        print("test mode is not permitted for the production project", file=sys.stderr)
        return 2
    if args.test_mode or args.once:
        try:
            if args.dry_run:
                result = sync.sync_once(dry_run=True)
            else:
                with sync.lock() as acquired:
                    if not acquired:
                        result = SyncResult("another_sync_is_running")
                    else:
                        sync.wait_for_stability()
                        result = sync.sync_once()
            print(f"sync result: {result.status}; candidate count: {result.staged_count}")
            return 0
        except (SyncError, NetworkFailure) as exc:
            print(f"sync failed: {exc}", file=sys.stderr)
            return 1
    _configure_logging(sync.repo_root)
    try:
        sync.run_forever()
    except SyncError as exc:
        logging.getLogger("civi-live-sync").error("daemon stopped: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
