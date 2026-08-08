from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from types import SimpleNamespace
from typing import BinaryIO, cast
from unittest import mock

import casefold_observatory.__main__ as module_entry
from casefold_observatory import cli, filesystem
from casefold_observatory.collision import (
    CollisionAnalysisError,
    CollisionErrorCode,
)
from casefold_observatory.corpus import (
    MAX_CORPUS_SOURCE_BYTES,
    CorpusErrorCode,
    CorpusIngestionError,
)
from casefold_observatory.filesystem import (
    CapturedFile,
    FileBoundaryError,
    FileBoundaryErrorCode,
)
from casefold_observatory.model import HazardHandling, TransformStep
from casefold_observatory.receipt import (
    DISTRIBUTION_VERSION,
    ReceiptErrorCode,
    ReceiptVerificationError,
)

_HEADER = b'{"schema":"casefold-observatory.identifier-corpus","schema_version":1}\n'
_SOURCE = _HEADER + b"".join(
    (
        b'{"identifier":"SS","record_id":"upper"}\n',
        b'{"identifier":"\\u00df","record_id":"eszett"}\n',
        b'{"identifier":"ss","record_id":"lower"}\n',
    )
)
_ANALYZE_ARGV = (
    "analyze",
    "--source",
    "source.jsonl",
    "--policy",
    "reject@case:lower,case:casefold",
    "--receipt",
    "result.receipt.json",
)
_VERIFY_ARGV = (
    "verify",
    "--source",
    "source.jsonl",
    "--receipt",
    "result.receipt.json",
)


def _invoke(argv: tuple[str, ...]) -> tuple[int, bytes, bytes]:
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    status = cli.main(argv, stdout=stdout, stderr=stderr)
    return status, stdout.getvalue(), stderr.getvalue()


def _json_line(value: bytes) -> dict[str, object]:
    testcase = unittest.TestCase()
    testcase.assertTrue(value.endswith(b"\n"))
    testcase.assertEqual(value.count(b"\n"), 1)
    testcase.assertTrue(value.isascii())
    document: object = json.loads(value)
    testcase.assertIs(type(document), dict)
    return cast(dict[str, object], document)


class _ZeroStream:
    def write(self, _data: bytes) -> int:
        return 0

    def flush(self) -> None:
        pass


def _assert_canonical_line(testcase: unittest.TestCase, value: bytes) -> None:
    document = _json_line(value)
    testcase.assertEqual(
        value,
        (
            json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii"),
    )


class CliParsingTests(unittest.TestCase):
    def test_static_help_and_version_are_exact_ascii(self) -> None:
        cases = (
            (("--help",), cli._TOP_HELP),
            (("analyze", "--help"), cli._ANALYZE_HELP),
            (("verify", "--help"), cli._VERIFY_HELP),
            (
                ("--version",),
                f"casefold-observatory {DISTRIBUTION_VERSION}\n".encode("ascii"),
            ),
        )
        for argv, expected in cases:
            with self.subTest(argv=argv):
                status, stdout, stderr = _invoke(argv)
                self.assertEqual(status, cli.EXIT_SUCCESS)
                self.assertEqual(stdout, expected)
                self.assertEqual(stderr, b"")
                self.assertTrue(stdout.isascii())
                self.assertNotIn(b"\x1b", stdout)

    def test_exact_grammar_rejects_unknown_missing_duplicate_and_dash_forms(
        self,
    ) -> None:
        cases = (
            (),
            ("help",),
            ("--help", "private-value"),
            ("analyze",),
            ("analyze", "--source", "source", "--receipt", "receipt"),
            (
                "analyze",
                "--receipt",
                "receipt",
                "--policy",
                "reject@case:lower",
                "--policy",
                "preserve@case:upper",
            ),
            (
                "analyze",
                "--source",
                "source",
                "--source",
                "second",
                "--policy",
                "reject@case:lower",
                "--receipt",
                "receipt",
            ),
            (
                "analyze",
                "--source=-",
                "source",
                "--policy",
                "reject@case:lower",
                "--receipt",
                "receipt",
            ),
            (
                "analyze",
                "--source",
                "-",
                "--policy",
                "reject@case:lower",
                "--receipt",
                "receipt",
            ),
            (
                "analyze",
                "--source",
                "source",
                "--policy",
                "reject@case:lower",
                "--receipt",
                "-",
            ),
            ("verify", "--source", "source"),
            (
                "verify",
                "--source",
                "source",
                "--source",
                "second",
            ),
            (
                "verify",
                "--receipt",
                "receipt",
                "--receipt",
                "second",
            ),
            (
                "verify",
                "--source",
                "source",
                "--receipt",
                "-",
            ),
            (
                "verify",
                "--source",
                "source",
                "--policy",
                "reject@case:lower",
            ),
            (
                "verify",
                "--source",
                "-",
                "--receipt",
                "receipt",
            ),
        )
        for argv in cases:
            with self.subTest(argument_count=len(argv)):
                status, stdout, stderr = _invoke(argv)
                self.assertEqual(status, cli.EXIT_USAGE)
                self.assertEqual(stdout, b"")
                self.assertEqual(
                    _json_line(stderr),
                    {"code": "usage.invalid_arguments", "status": "error"},
                )

    def test_policy_argument_grammar_is_ascii_explicit_and_bounded(self) -> None:
        policy = cli._parse_policy_argument(
            "preserve@normalize:nfc,normalize:nfd,normalize:nfkc,"
            "normalize:nfkd,case:lower,case:upper,case:casefold"
        )
        self.assertEqual(
            tuple(step.value for step in policy.steps),
            tuple(step.value for step in TransformStep),
        )
        self.assertIs(policy.hazard_handling, HazardHandling.PRESERVE)

        invalid = (
            "",
            "reject",
            "reject@@case:lower",
            "implicit@case:lower",
            "reject@",
            "reject@case:lower,",
            "reject@private:step",
            "reject@" + ",".join(("case:lower",) * 9),
            "reject@case:lower\N{SNOWMAN}",
            "reject@" + "x" * (cli.MAX_POLICY_ARGUMENT_BYTES + 1),
        )
        for value in invalid:
            with self.subTest(length=len(value)):
                status, stdout, stderr = _invoke(
                    (
                        "analyze",
                        "--source",
                        "source",
                        "--policy",
                        value,
                        "--receipt",
                        "receipt",
                    )
                )
                self.assertEqual(status, cli.EXIT_POLICY)
                self.assertEqual(stdout, b"")
                self.assertEqual(
                    _json_line(stderr),
                    {"code": "policy.invalid_argument", "status": "error"},
                )

    def test_more_than_eight_policy_arguments_is_policy_rejection(self) -> None:
        argv = ["analyze", "--source", "source", "--receipt", "receipt"]
        for _ in range(9):
            argv.extend(("--policy", "reject@case:lower"))
        status, stdout, stderr = _invoke(tuple(argv))
        self.assertEqual(status, cli.EXIT_POLICY)
        self.assertEqual(stdout, b"")
        self.assertEqual(_json_line(stderr)["code"], "policy.invalid_argument")

    def test_policy_order_is_preserved_and_option_order_is_not_semantic(self) -> None:
        command = cli._parse_command(
            (
                "analyze",
                "--policy",
                "preserve@case:upper",
                "--receipt",
                "receipt",
                "--source",
                "source",
                "--policy",
                "reject@case:lower",
            )
        )
        self.assertIs(type(command), cli._AnalyzeCommand)
        analyzed = cast(cli._AnalyzeCommand, command)
        self.assertEqual(
            tuple(policy.hazard_handling.value for policy in analyzed.policies),
            ("preserve", "reject"),
        )
        self.assertEqual(analyzed.source_path, "source")
        self.assertEqual(analyzed.receipt_path, "receipt")

        verified = cli._parse_command(
            ("verify", "--receipt", "receipt", "--source", "source")
        )
        self.assertEqual(
            verified,
            cli._VerifyCommand(source_path="source", receipt_path="receipt"),
        )

    def test_forged_argv_container_is_internal_not_echoed(self) -> None:
        status, output, error = cli._dispatch(cast(tuple[str, ...], ["private-value"]))
        self.assertEqual(status, cli.EXIT_INTERNAL)
        self.assertEqual(output, b"")
        self.assertEqual(
            _json_line(error),
            {"code": "internal.unexpected", "status": "error"},
        )


class CliWorkflowTests(unittest.TestCase):
    def test_analyze_and_verify_real_files_with_safe_summaries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-cli-workflow-") as directory:
            root = Path(directory)
            source = root / "source.jsonl"
            receipt = root / "result.receipt.json"
            source.write_bytes(_SOURCE)

            analyze_status, analyze_stdout, analyze_stderr = _invoke(
                (
                    "analyze",
                    "--source",
                    source.as_posix(),
                    "--policy",
                    "reject@case:lower,case:casefold",
                    "--receipt",
                    receipt.as_posix(),
                )
            )

            self.assertEqual(analyze_status, cli.EXIT_SUCCESS)
            self.assertEqual(analyze_stderr, b"")
            summary = _json_line(analyze_stdout)
            self.assertEqual(summary["status"], "analyzed")
            self.assertEqual(summary["record_count"], 3)
            self.assertEqual(summary["colliding_record_count"], 3)
            self.assertEqual(summary["component_count"], 1)
            self.assertEqual(summary["policy_group_count"], 1)
            self.assertEqual(summary["witness_count"], 2)
            receipt_bytes = receipt.read_bytes()
            self.assertEqual(
                summary["receipt_sha256"],
                hashlib.sha256(receipt_bytes).hexdigest(),
            )
            info = receipt.stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_nlink, 1)
            self.assertNotIn(receipt_bytes, analyze_stdout)
            _assert_canonical_line(self, analyze_stdout)

            verify_status, verify_stdout, verify_stderr = _invoke(
                (
                    "verify",
                    "--source",
                    source.as_posix(),
                    "--receipt",
                    receipt.as_posix(),
                )
            )
            self.assertEqual(verify_status, cli.EXIT_SUCCESS)
            self.assertEqual(verify_stderr, b"")
            self.assertEqual(
                _json_line(verify_stdout),
                {
                    "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
                    "status": "verified",
                },
            )
            _assert_canonical_line(self, verify_stdout)

    def test_existing_destination_and_input_output_alias_never_clobber(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="casefold-cli-no-clobber-"
        ) as directory:
            root = Path(directory)
            source = root / "source.jsonl"
            source.write_bytes(_SOURCE)
            existing = root / "existing.receipt.json"
            existing.write_bytes(b"private-existing")

            status, stdout, stderr = _invoke(
                (
                    "analyze",
                    "--source",
                    source.as_posix(),
                    "--policy",
                    "reject@case:lower",
                    "--receipt",
                    existing.as_posix(),
                )
            )
            self.assertEqual(status, cli.EXIT_FILESYSTEM)
            self.assertEqual(stdout, b"")
            self.assertEqual(
                _json_line(stderr)["code"],
                "filesystem.destination_exists",
            )
            self.assertEqual(existing.read_bytes(), b"private-existing")

            status, stdout, stderr = _invoke(
                (
                    "analyze",
                    "--source",
                    source.as_posix(),
                    "--policy",
                    "reject@case:lower",
                    "--receipt",
                    source.as_posix(),
                )
            )
            self.assertEqual(status, cli.EXIT_FILESYSTEM)
            self.assertEqual(stdout, b"")
            self.assertEqual(_json_line(stderr)["code"], "filesystem.alias")
            self.assertEqual(source.read_bytes(), _SOURCE)

    def test_digest_replay_mismatch_is_exit_four(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-cli-mismatch-") as directory:
            root = Path(directory)
            source = root / "source.jsonl"
            receipt = root / "receipt.json"
            source.write_bytes(_SOURCE)
            status, _stdout, _stderr = _invoke(
                (
                    "analyze",
                    "--source",
                    source.as_posix(),
                    "--policy",
                    "reject@case:lower",
                    "--receipt",
                    receipt.as_posix(),
                )
            )
            self.assertEqual(status, cli.EXIT_SUCCESS)
            source.write_bytes(_HEADER)

            status, stdout, stderr = _invoke(
                (
                    "verify",
                    "--source",
                    source.as_posix(),
                    "--receipt",
                    receipt.as_posix(),
                )
            )
            self.assertEqual(status, cli.EXIT_MISMATCH)
            self.assertEqual(stdout, b"")
            self.assertEqual(
                _json_line(stderr)["code"],
                "receipt.source_mismatch",
            )

    def test_symlink_and_oversized_source_use_filesystem_and_resource_exits(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="casefold-cli-boundaries-"
        ) as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(_SOURCE)
            symlink = root / "source-link"
            symlink.symlink_to(source.name)
            status, stdout, stderr = _invoke(
                (
                    "analyze",
                    "--source",
                    symlink.as_posix(),
                    "--policy",
                    "reject@case:lower",
                    "--receipt",
                    (root / "receipt").as_posix(),
                )
            )
            self.assertEqual(status, cli.EXIT_FILESYSTEM)
            self.assertEqual(stdout, b"")
            self.assertEqual(_json_line(stderr)["code"], "filesystem.symlink")

            oversized = root / "oversized"
            oversized.write_bytes(b"x" * (MAX_CORPUS_SOURCE_BYTES + 1))
            status, stdout, stderr = _invoke(
                (
                    "analyze",
                    "--source",
                    oversized.as_posix(),
                    "--policy",
                    "reject@case:lower",
                    "--receipt",
                    (root / "other-receipt").as_posix(),
                )
            )
            self.assertEqual(status, cli.EXIT_POLICY)
            self.assertEqual(stdout, b"")
            self.assertEqual(_json_line(stderr)["code"], "filesystem.read_limit")

    def test_stdin_is_not_a_source_and_errors_never_echo_paths_or_values(self) -> None:
        private = "PRIVATE-PATH-AND-VALUE"
        status, stdout, stderr = _invoke(
            (
                "analyze",
                "--source",
                private,
                "--policy",
                "reject@case:lower",
                "--receipt",
                "receipt",
            )
        )
        self.assertEqual(status, cli.EXIT_FILESYSTEM)
        self.assertEqual(stdout, b"")
        self.assertNotIn(private.encode(), stderr)
        self.assertLess(len(stderr), 256)
        _assert_canonical_line(self, stderr)


class CliErrorTaxonomyTests(unittest.TestCase):
    def test_every_corpus_code_maps_to_syntax_or_resource_exit(self) -> None:
        resource = {
            CorpusErrorCode.JSON_DEPTH,
            CorpusErrorCode.LINE_COUNT,
            CorpusErrorCode.LINE_TOO_LARGE,
            CorpusErrorCode.SOURCE_TOO_LARGE,
        }
        for code in CorpusErrorCode:
            error = CorpusIngestionError(
                code,
                physical_line_ordinal=2,
                input_record_ordinal=1,
            )
            with (
                self.subTest(code=code),
                mock.patch.object(cli, "_analyze", side_effect=error),
            ):
                status, stdout, stderr = cli._dispatch(_ANALYZE_ARGV)
                self.assertEqual(
                    status,
                    cli.EXIT_POLICY if code in resource else cli.EXIT_USAGE,
                )
                self.assertEqual(stdout, b"")
                self.assertEqual(
                    _json_line(stderr),
                    {
                        "code": f"corpus.{code.value}",
                        "input_record_ordinal": 1,
                        "physical_line_ordinal": 2,
                        "status": "error",
                    },
                )

    def test_every_collision_code_maps_to_policy_exit_with_ordinals(self) -> None:
        for code in CollisionErrorCode:
            error = CollisionAnalysisError(
                code,
                input_record_ordinal=3,
                canonical_record_ordinal=2,
                policy_ordinal=1,
            )
            with (
                self.subTest(code=code),
                mock.patch.object(cli, "_analyze", side_effect=error),
            ):
                status, stdout, stderr = cli._dispatch(_ANALYZE_ARGV)
                self.assertEqual(status, cli.EXIT_POLICY)
                self.assertEqual(stdout, b"")
                self.assertEqual(
                    _json_line(stderr),
                    {
                        "canonical_record_ordinal": 2,
                        "code": f"collision.{code.value}",
                        "input_record_ordinal": 3,
                        "policy_ordinal": 1,
                        "status": "error",
                    },
                )

    def test_every_receipt_code_maps_to_schema_resource_or_mismatch_exit(
        self,
    ) -> None:
        schema = {
            ReceiptErrorCode.DUPLICATE_KEY,
            ReceiptErrorCode.INVALID_JSON,
            ReceiptErrorCode.INVALID_RECEIPT,
            ReceiptErrorCode.NONCANONICAL_RECEIPT,
            ReceiptErrorCode.SCHEMA_MISMATCH,
        }
        resource = {
            ReceiptErrorCode.JSON_DEPTH,
            ReceiptErrorCode.RECEIPT_TOO_LARGE,
        }
        for code in ReceiptErrorCode:
            error = ReceiptVerificationError(code, policy_ordinal=1)
            with (
                self.subTest(code=code),
                mock.patch.object(cli, "_verify", side_effect=error),
            ):
                status, stdout, stderr = cli._dispatch(_VERIFY_ARGV)
                expected = (
                    cli.EXIT_USAGE
                    if code in schema
                    else cli.EXIT_POLICY
                    if code in resource
                    else cli.EXIT_MISMATCH
                )
                self.assertEqual(status, expected)
                self.assertEqual(stdout, b"")
                self.assertEqual(
                    _json_line(stderr),
                    {
                        "code": f"receipt.{code.value}",
                        "policy_ordinal": 1,
                        "status": "error",
                    },
                )

    def test_every_file_code_maps_to_filesystem_except_read_limit(self) -> None:
        for code in FileBoundaryErrorCode:
            with (
                self.subTest(code=code),
                mock.patch.object(
                    cli,
                    "_verify",
                    side_effect=FileBoundaryError(code),
                ),
            ):
                status, stdout, stderr = cli._dispatch(_VERIFY_ARGV)
                self.assertEqual(
                    status,
                    (
                        cli.EXIT_POLICY
                        if code is FileBoundaryErrorCode.READ_LIMIT
                        else cli.EXIT_FILESYSTEM
                    ),
                )
                self.assertEqual(stdout, b"")
                self.assertEqual(
                    _json_line(stderr),
                    {
                        "code": f"filesystem.{code.value}",
                        "status": "error",
                    },
                )

    def test_interrupt_and_unexpected_failures_are_bounded_and_redacted(self) -> None:
        cases: tuple[tuple[BaseException, str], ...] = (
            (KeyboardInterrupt(), "internal.interrupted"),
            (RuntimeError("PRIVATE-VALUE"), "internal.unexpected"),
        )
        for failure, code in cases:
            with (
                self.subTest(code=code),
                mock.patch.object(cli, "_verify", side_effect=failure),
            ):
                status, stdout, stderr = cli._dispatch(_VERIFY_ARGV)
                self.assertEqual(status, cli.EXIT_INTERNAL)
                self.assertEqual(stdout, b"")
                self.assertEqual(
                    _json_line(stderr),
                    {"code": code, "status": "error"},
                )
                self.assertNotIn(b"PRIVATE", stderr)


class CliChannelTests(unittest.TestCase):
    def test_binary_channel_short_writes_and_interrupts_are_retried(self) -> None:
        stream = io.BytesIO()
        original_write = stream.write
        interrupted = True

        def write_one(data: bytes) -> int:
            nonlocal interrupted
            if interrupted:
                interrupted = False
                raise InterruptedError
            return original_write(data[:1])

        with mock.patch.object(stream, "write", side_effect=write_one):
            cli._write_all(stream, b"ascii\n")
        self.assertEqual(stream.getvalue(), b"ascii\n")

    def test_failed_channel_write_returns_internal_without_traceback(self) -> None:
        output = cast(BinaryIO, _ZeroStream())
        status = cli.main(("--version",), stdout=output, stderr=io.BytesIO())
        self.assertEqual(status, cli.EXIT_INTERNAL)

    def test_default_binary_streams_and_argv_are_used(self) -> None:
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        with (
            mock.patch.object(sys, "argv", ["casefold-observatory", "--version"]),
            mock.patch.object(sys, "stdout", SimpleNamespace(buffer=stdout)),
            mock.patch.object(sys, "stderr", SimpleNamespace(buffer=stderr)),
        ):
            status = cli.main()
        self.assertEqual(status, cli.EXIT_SUCCESS)
        self.assertEqual(
            stdout.getvalue(),
            f"casefold-observatory {DISTRIBUTION_VERSION}\n".encode(),
        )
        self.assertEqual(stderr.getvalue(), b"")

    def test_missing_binary_default_stream_is_internal(self) -> None:
        with mock.patch.object(sys, "stdout", SimpleNamespace()):
            status = cli.main(("--version",), stderr=io.BytesIO())
        self.assertEqual(status, cli.EXIT_INTERNAL)


class CliInternalAndInstalledTests(unittest.TestCase):
    def test_verify_rejects_same_descriptor_identity_before_replay(self) -> None:
        captured = CapturedFile(data=b"private", device=1, inode=2)
        with (
            mock.patch.object(
                cli,
                "capture_regular_file",
                side_effect=(captured, captured),
            ),
            mock.patch.object(cli, "verify_collision_receipt") as verify,
        ):
            status, stdout, stderr = cli._dispatch(_VERIFY_ARGV)
        self.assertEqual(status, cli.EXIT_FILESYSTEM)
        self.assertEqual(stdout, b"")
        self.assertEqual(_json_line(stderr)["code"], "filesystem.alias")
        verify.assert_not_called()

    def test_runtime_modules_have_no_network_config_shell_or_generic_open(self) -> None:
        forbidden_imports = {
            "argparse",
            "configparser",
            "http",
            "pathlib",
            "requests",
            "socket",
            "subprocess",
            "urllib",
        }
        paths = (
            Path(cli.__file__),
            Path(filesystem.__file__),
        )
        for target in paths:
            tree = ast.parse(target.read_text(encoding="utf-8"))
            imports: set[str] = set()
            calls: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module is not None:
                    imports.add(node.module.split(".")[0])
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    calls.add(node.func.id)
            with self.subTest(module=target.name):
                self.assertTrue(forbidden_imports.isdisjoint(imports))
                self.assertNotIn("open", calls)

    def test_module_entry_false_and_true_paths_share_cli_main(self) -> None:
        self.assertTrue(callable(getattr(module_entry, "main", None)))
        loaded_entry = sys.modules.pop("casefold_observatory.__main__")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", RuntimeWarning)
                with (
                    mock.patch.object(cli, "main", return_value=7) as entry,
                    self.assertRaises(SystemExit) as caught,
                ):
                    runpy.run_module(
                        "casefold_observatory.__main__",
                        run_name="__main__",
                    )
        finally:
            sys.modules["casefold_observatory.__main__"] = loaded_entry

        self.assertIs(sys.modules["casefold_observatory.__main__"], loaded_entry)
        self.assertEqual(caught.exception.code, 7)
        entry.assert_called_once_with()

    def test_installed_console_and_module_have_byte_exact_parity(self) -> None:
        console = Path(sys.executable).with_name("casefold-observatory")
        self.assertTrue(console.is_file())
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        commands = (
            ("--version",),
            ("--help",),
            ("verify", "--source", "PRIVATE-PATH"),
        )
        for arguments in commands:
            with self.subTest(arguments=arguments):
                console_result = subprocess.run(
                    (console.as_posix(), *arguments),
                    input=b"PRIVATE-STDIN",
                    capture_output=True,
                    env=environment,
                    check=False,
                )
                module_result = subprocess.run(
                    (
                        sys.executable,
                        "-m",
                        "casefold_observatory",
                        *arguments,
                    ),
                    input=b"PRIVATE-STDIN",
                    capture_output=True,
                    env=environment,
                    check=False,
                )
                self.assertEqual(console_result.returncode, module_result.returncode)
                self.assertEqual(console_result.stdout, module_result.stdout)
                self.assertEqual(console_result.stderr, module_result.stderr)
                self.assertNotIn(b"PRIVATE", console_result.stderr)


if __name__ == "__main__":
    unittest.main()
