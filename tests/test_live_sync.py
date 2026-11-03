import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("civi_live_sync", PROJECT / "tools/live-sync.py")
live_sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = live_sync
SPEC.loader.exec_module(live_sync)


def git(cwd, *args, check=True):
    result = subprocess.run(
        ["git", *args], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if check and result.returncode != 0:
        raise AssertionError(f"git {args[0]} failed ({result.returncode})")
    return result


class RepoFixture:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="civi-live-sync-")
        self.base = Path(self.temporary.name)
        self.remote = self.base / "origin.git"
        self.root = self.base / "worktree"
        git(self.base, "init", "--bare", "--initial-branch=main", str(self.remote))
        git(self.base, "init", "--initial-branch=main", str(self.root))
        git(self.root, "config", "user.name", "Test User")
        git(self.root, "config", "user.email", "test@example.invalid")
        (self.root / ".gitignore").write_text(
            ".toolchain/\n.gradle/\nbuild/\ndist/\nlocal.properties\n", encoding="utf-8",
        )
        (self.root / "README.md").write_text("test project\n", encoding="utf-8")
        git(self.root, "add", ".gitignore", "README.md")
        git(self.root, "commit", "-m", "initial test project")
        git(self.root, "remote", "add", "origin", str(self.remote))
        git(self.root, "push", "-u", "origin", "main")
        self.sync = live_sync.LiveSync(self.root, test_origin=str(self.remote),
                                       debounce_seconds=0, poll_seconds=0)

    def close(self):
        self.temporary.cleanup()


class LiveSyncPolicyTests(unittest.TestCase):
    def test_approved_origins_reject_credentials_and_other_repositories(self):
        self.assertTrue(live_sync.is_approved_github_origin(
            "https://github.com/an-stu/CiviAdShield.git"))
        self.assertTrue(live_sync.is_approved_github_origin(
            "git@github.com:an-stu/CiviAdShield.git"))
        self.assertTrue(live_sync.is_approved_github_origin(
            "ssh://git@github.com/an-stu/CiviAdShield"))
        self.assertFalse(live_sync.is_approved_github_origin(
            "https://token@github.com/an-stu/CiviAdShield.git"))
        self.assertFalse(live_sync.is_approved_github_origin(
            "https://github.com/other/CiviAdShield.git"))
        self.assertFalse(live_sync.is_approved_github_origin(
            "https://github.com/an-stu/CiviAdShield.git?token=secret"))
        self.assertFalse(live_sync.is_approved_github_origin(
            "git@github.com:an-stu/Other.git"))

    def test_candidate_allowlist_and_pretracked_wrapper_exception(self):
        self.assertTrue(live_sync.is_candidate_path("app/src/main/A.java", False))
        self.assertTrue(live_sync.is_candidate_path("app/src/main/assets/rules.txt", False))
        self.assertTrue(live_sync.is_candidate_path("docs/SYNC.md", False))
        self.assertTrue(live_sync.is_candidate_path("tools/live-sync.py", False))
        self.assertFalse(live_sync.is_candidate_path("docs/runtime.json", False))
        self.assertFalse(live_sync.is_candidate_path("docs/subdir/SYNC.md", False))
        self.assertFalse(live_sync.is_candidate_path("dist/release.apk", False))
        self.assertFalse(live_sync.is_candidate_path(".toolchain/keys.txt", False))
        self.assertFalse(live_sync.is_candidate_path("local.properties", True))
        self.assertTrue(live_sync.is_candidate_path("gradle/wrapper/gradle-wrapper.jar", True))
        self.assertFalse(live_sync.is_candidate_path("gradle/wrapper/gradle-wrapper.jar", False))
        self.assertFalse(live_sync.is_candidate_path("SETUP-NOTES.txt", False))
        self.assertTrue(live_sync.is_candidate_path("SETUP-NOTES.txt", True))

    def test_sensitive_content_patterns_are_blocked(self):
        self.assertTrue(live_sync.contains_private_material(
            b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\n"))
        self.assertTrue(live_sync.contains_private_material(b"ghp_" + b"a" * 20))
        self.assertTrue(live_sync.contains_private_material(b"gho_" + b"b" * 25))
        self.assertTrue(live_sync.contains_private_material(b"github_pat_" + b"c" * 30))
        self.assertFalse(live_sync.contains_private_material(b"ghp_short"))
        self.assertFalse(live_sync.is_text_content(b"binary\x00content"))

    def test_network_git_calls_are_noninteractive_and_bounded(self):
        with tempfile.TemporaryDirectory(prefix="civi-live-sync-empty-") as temporary:
            sync = live_sync.LiveSync(Path(temporary), test_origin="unused")
            observed = {}

            def timeout_run(command, **kwargs):
                observed.update(kwargs)
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])

            with patch.object(live_sync.subprocess, "run", side_effect=timeout_run):
                with self.assertRaises(live_sync.NetworkFailure):
                    sync._git(["fetch", "origin", "main"], check=False)
            self.assertEqual(45.0, observed["timeout"])
            self.assertEqual("0", observed["env"]["GIT_TERMINAL_PROMPT"])


class LiveSyncGitTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RepoFixture()
        self.addCleanup(self.fixture.close)

    def test_sync_commits_and_pushes_only_allowlisted_source(self):
        root = self.fixture.root
        source = root / "app/src/main/Probe.java"
        source.parent.mkdir(parents=True)
        source.write_text("package example;\nfinal class Probe {}\n", encoding="utf-8")
        (root / "dist").mkdir()
        (root / "dist/release.apk").write_bytes(b"artifact")
        (root / ".toolchain").mkdir()
        (root / ".toolchain/local-data.txt").write_text("private local data", encoding="utf-8")
        (root / "docs").mkdir()
        (root / "docs/runtime.json").write_text("{}", encoding="utf-8")

        result = self.fixture.sync.sync_once()

        self.assertEqual("synced", result.status)
        self.assertEqual(1, result.staged_count)
        tree = git(self.fixture.remote, "--git-dir", str(self.fixture.remote),
                   "ls-tree", "-r", "--name-only", "main").stdout.decode().splitlines()
        self.assertIn("app/src/main/Probe.java", tree)
        self.assertNotIn("dist/release.apk", tree)
        self.assertNotIn(".toolchain/local-data.txt", tree)
        self.assertNotIn("docs/runtime.json", tree)
        self.assertEqual("chore: sync local source changes",
                         git(root, "log", "-1", "--format=%s").stdout.decode().strip())

    def test_blocks_private_key_or_token_before_staging(self):
        secret = self.fixture.root / "tools/leaked.txt"
        secret.parent.mkdir()
        secret.write_text("-----BEGIN " + "PRIVATE KEY-----\n", encoding="utf-8")

        result = self.fixture.sync.sync_once()

        self.assertEqual("blocked_unsafe_content", result.status)
        self.assertEqual(b"", git(self.fixture.root, "diff", "--cached", "--name-only").stdout)
        self.assertEqual("initial test project",
                         git(self.fixture.root, "log", "-1", "--format=%s").stdout.decode().strip())

    def test_preserves_user_staged_changes_and_skips(self):
        readme = self.fixture.root / "README.md"
        readme.write_text("staged by user\n", encoding="utf-8")
        git(self.fixture.root, "add", "README.md")

        result = self.fixture.sync.sync_once()

        self.assertEqual("staged_changes_present", result.status)
        self.assertEqual("README.md", git(self.fixture.root, "diff", "--cached", "--name-only")
                         .stdout.decode().strip())
        self.assertEqual("initial test project",
                         git(self.fixture.root, "log", "-1", "--format=%s").stdout.decode().strip())

    def test_skips_wrong_branch_and_unapproved_remote(self):
        git(self.fixture.root, "checkout", "-b", "feature")
        with self.assertRaises(live_sync.SyncError):
            self.fixture.sync.validate_repository()
        git(self.fixture.root, "checkout", "main")
        git(self.fixture.root, "remote", "set-url", "origin", "https://github.com/other/project.git")
        with self.assertRaises(live_sync.SyncError):
            self.fixture.sync.validate_repository()

    def test_fast_forwards_a_clean_checkout_when_origin_is_ahead(self):
        peer = self.fixture.base / "peer"
        git(self.fixture.base, "clone", str(self.fixture.remote), str(peer))
        git(peer, "config", "user.name", "Remote User")
        git(peer, "config", "user.email", "remote@example.invalid")
        (peer / "README.md").write_text("remote update\n", encoding="utf-8")
        git(peer, "commit", "-am", "remote source update")
        git(peer, "push", "origin", "main")

        result = self.fixture.sync.sync_once()

        self.assertEqual("fast_forwarded", result.status)
        local_head = git(self.fixture.root, "rev-parse", "HEAD").stdout.strip()
        remote_head = git(self.fixture.remote, "--git-dir", str(self.fixture.remote),
                          "rev-parse", "refs/heads/main").stdout.strip()
        self.assertEqual(remote_head, local_head)

    def test_does_not_merge_or_push_when_origin_is_ahead_with_local_changes(self):
        peer = self.fixture.base / "peer"
        git(self.fixture.base, "clone", str(self.fixture.remote), str(peer))
        git(peer, "config", "user.name", "Remote User")
        git(peer, "config", "user.email", "remote@example.invalid")
        (peer / "README.md").write_text("remote update\n", encoding="utf-8")
        git(peer, "commit", "-am", "remote source update")
        git(peer, "push", "origin", "main")
        source = self.fixture.root / "app/src/Local.java"
        source.parent.mkdir(parents=True)
        source.write_text("final class Local {}\n", encoding="utf-8")

        result = self.fixture.sync.sync_once()

        self.assertEqual("needs_manual_merge", result.status)
        self.assertFalse(source.relative_to(self.fixture.root).as_posix() in
                         git(self.fixture.remote, "--git-dir", str(self.fixture.remote),
                             "ls-tree", "-r", "--name-only", "main").stdout.decode().splitlines())
        self.assertEqual(b"", git(self.fixture.root, "diff", "--cached", "--name-only").stdout)

    def test_commits_source_deletion_without_including_other_staged_paths(self):
        existing = self.fixture.root / "app/src/Old.java"
        existing.parent.mkdir(parents=True)
        existing.write_text("final class Old {}\n", encoding="utf-8")
        git(self.fixture.root, "add", "app/src/Old.java")
        git(self.fixture.root, "commit", "-m", "add fixture source")
        git(self.fixture.root, "push", "origin", "main")
        existing.unlink()

        result = self.fixture.sync.sync_once()

        self.assertEqual("synced", result.status)
        tree = git(self.fixture.remote, "--git-dir", str(self.fixture.remote),
                   "ls-tree", "-r", "--name-only", "main").stdout.decode().splitlines()
        self.assertNotIn("app/src/Old.java", tree)


if __name__ == "__main__":
    unittest.main()
