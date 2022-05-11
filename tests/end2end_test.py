import os
import sys
import platform
import unittest
from pathlib import Path

import yaml
import distro

from disassemble_reassemble_check import (
    disassemble_reassemble_test as drt,
    skip_reassemble,
)


def compatible_test(config, test):
    # Check the test case is compatible with this platform.
    if "platform" in config:
        if platform.system() not in config["platform"]:
            return False

    # Check the test case is compatible with this distro.
    if "distro" in config:
        if distro.name() not in config["distro"]["name"]:
            return False
        if distro.version() not in config["distro"]["version"]:
            return False

    # Individual test can also be deactivated for a distro

    # Check the test case is compatible with this platform.
    if "platform" in test:
        if platform.system() not in test["platform"]:
            return False

    # Check the test case is compatible with this distro.
    if "distro" in test:
        if distro.name() not in test["distro"]["name"]:
            return False
        if distro.version() not in test["distro"]["version"]:
            return False

    # TODO: Can we have a hybrid x86_32 and x86_64 vcvar environment?
    if "platform" in config and "arch" in test:
        if "Windows" in config["platform"]:
            if os.environ["VSCMD_ARG_TGT_ARCH"] != test["arch"]:
                return False
    return True


class TestExamples(unittest.TestCase):
    def setUp(self):
        self.configs = Path("./tests/").glob("*.yaml")
        if __name__ == "__main__" and sys.argv[1:]:
            self.configs = [
                arg for arg in sys.argv[1:] if arg.endswith(".yaml")
            ]

    @unittest.skipUnless(
        platform.system() == "Linux", "This test is linux only."
    )
    def test_1(self):
        self.assertTrue(
            drt(
                "examples/ex1",
                "ex",
                skip_test=True,
                reassemble_function=skip_reassemble,
                optimizations=[],
            )
        )

    def test_examples(self):
        for path in self.configs:
            # Parse YAML config file.
            with open(str(path)) as f:
                config = yaml.safe_load(f)
            # Run all test cases for this host.
            for test in config["tests"]:
                with self.subTest(test=test):
                    if not compatible_test(config, test):
                        self.skipTest("skipping incompatible test")
                    self.disassemble_example(test)

    def disassemble_example(self, config):
        path = Path(config["path"]) / config["name"]
        binary = config.get("binary", config["name"])
        args = {
            "extra_compile_flags": config["build"]["flags"],
            "extra_reassemble_flags": config["reassemble"]["flags"],
            "extra_link_flags": config.get("link", {}).get("flags", []),
            "linker": config.get("link", {}).get("linker"),
            "reassembly_compiler": config["reassemble"]["compiler"],
            "c_compilers": config["build"]["c"],
            "cxx_compilers": config["build"]["cpp"],
            "optimizations": config["build"]["optimizations"],
            "strip_exe": config["test"]["strip_exe"],
            "strip": config["test"].get("strip", False),
            "sstrip": config["test"].get("sstrip", False),
            "skip_test": config["test"].get("skip", False),
            "check_cfg": config["test"].get("check_cfg", False),
            "exec_wrapper": config["test"].get("wrapper"),
            "arch": config.get("arch"),
            "extra_ddisasm_args": config.get("disassemble", {}).get(
                "args", []
            ),
        }
        if config["reassemble"].get("skip", False):
            args["reassemble_function"] = skip_reassemble
        self.assertTrue(drt(path, binary, **args))


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1])
