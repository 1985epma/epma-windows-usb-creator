"""The built-in documentation (Help menu) must stay in step with the program.

Everything it states that can drift - commands, exit codes, environment variables,
thresholds, messages, the audit log path - is checked here against the code itself.
No window is needed: the documentation is plain data (`help_sections()`).
"""
import re
import unittest

from tests.helpers import app


def sections():
    return dict(app.help_sections())


def all_text():
    return "\n".join(f"{title}\n{body}" for title, body in app.help_sections())


class StructureTests(unittest.TestCase):
    def test_every_section_has_a_unique_title_and_a_body(self):
        pairs = app.help_sections()
        titles = [t for t, _b in pairs]
        self.assertEqual(len(titles), len(set(titles)))
        for title, body in pairs:
            with self.subTest(title=title):
                self.assertTrue(title.strip())
                self.assertGreater(len(body.strip()), 80)

    def test_expected_sections_exist_in_a_sensible_order(self):
        titles = [t for t, _b in app.help_sections()]
        self.assertEqual(titles[0], "Overview")
        self.assertEqual(titles[-1], "About")
        for needed in ("Quick start: Windows 11", "Quick start: Linux and other ISOs", "Safety",
                       "Verification and eject", "Command line", "Troubleshooting"):
            self.assertIn(needed, titles)

    def test_lines_use_only_the_supported_markup(self):
        for title, body in app.help_sections():
            for line in body.splitlines():
                with self.subTest(title=title, line=line[:40]):
                    self.assertFalse(line.startswith("##") and not line.startswith("## "), line)
                    self.assertFalse(line.startswith("•") and not line.startswith("• "), line)

    def test_no_unformatted_placeholders_are_left(self):
        self.assertNotRegex(all_text(), r"\{[A-Za-z_]+\}")
        self.assertNotIn("@HOSTS@", all_text())
        self.assertNotIn("noqa", all_text())  # a lint comment must never end up inside the text


class MatchesTheCodeTests(unittest.TestCase):
    def test_every_cli_command_is_documented(self):
        parser = app.build_cli_parser()
        commands = set()
        for action in parser._actions:
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                commands.update(choices)
        self.assertTrue(commands, "could not read the sub-commands from the parser")
        text = sections()["Command line"]
        for command in commands:
            with self.subTest(command=command):
                self.assertRegex(text, r"(?m)^• " + re.escape(command) + r"\b")

    def test_every_exit_code_is_documented_with_its_value(self):
        text = sections()["Command line"]
        for name in ("EXIT_OK", "EXIT_ERROR", "EXIT_USAGE", "EXIT_VERIFY_FAILED", "EXIT_EJECT_FAILED",
                     "EXIT_INTERRUPTED"):
            with self.subTest(code=name):
                self.assertRegex(text, r"(?m)^• " + str(getattr(app, name)) + r" ")

    def test_the_documented_write_flags_exist_in_the_parser(self):
        parser = app.build_cli_parser()
        write_help = None
        for action in parser._actions:
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict) and "write" in choices:
                write_help = choices["write"].format_help()
        self.assertIsNotNone(write_help)
        for flag in ("--iso", "--disk", "--mode", "--dry-run", "--yes", "--no-eject", "--json"):
            with self.subTest(flag=flag):
                self.assertIn(flag, write_help)
                self.assertIn(flag, sections()["Command line"])
        # verification is not optional and the help must not suggest otherwise
        self.assertNotIn("--no-verify", write_help)
        self.assertNotIn("--no-verify", all_text())
        self.assertIn("cannot be skipped", sections()["Verification and eject"])

    def test_environment_variables_come_from_the_code(self):
        text = sections()["Files, logs and settings"]
        for name in (app.ENV_AUDIT_LOG, app.ENV_DISABLE_AUDIT_LOG, app.ENV_TRUSTED_HOSTS,
                     app.ENV_ALLOW_ANY_HOST, app.ENV_EXPECTED_SHA256, app.ENV_LANG):
            with self.subTest(variable=name):
                self.assertIn(name, text)

    def test_the_audit_log_path_is_the_real_one(self):
        self.assertIn(app.audit_log_path(), sections()["Files, logs and settings"])

    def test_risk_thresholds_match_the_constants(self):
        text = sections()["Tab 2: Create USB drive"]
        self.assertIn(f"larger than {app.LARGE_DISK_BYTES // 1024 ** 3} GB", text)
        self.assertIn(f"{app.SUBSTANTIAL_USED_BYTES // 1024 ** 3} GB or more in use", text)
        self.assertIn(f"{app.MANY_VOLUMES} or more volumes", text)

    def test_trusted_download_hosts_are_listed(self):
        text = sections()["Tab 1: Download ISO"]
        for host in app.DEFAULT_TRUSTED_ISO_HOSTS:
            with self.subTest(host=host):
                self.assertIn(host, text)

    def test_version_license_and_project_link(self):
        about = sections()["About"]
        self.assertIn(app.__version__, about)
        self.assertIn(app.PROJECT_URL, about)
        self.assertIn("GNU General Public License v3", about)
        self.assertIn(f"EPMA USB CREATOR {app.__version__}", sections()["Overview"])

    def test_filesystem_label_matches(self):
        self.assertIn(app.VOL_NAME, sections()["Overview"])

    def test_quoted_messages_exist_in_the_code(self):
        # Troubleshooting quotes the exact messages users will see. If one is reworded in the
        # code, the documentation must be reworded too (this test then fails).
        import inspect
        source = inspect.getsource(app)
        documentation = all_text()
        for message in ("Could not find sources/install.wim or sources/install.esd on the ISO",
                        "This ISO is not a bootable hybrid image",
                        "Aborted for safety",
                        "Neither 'sudo' nor 'pkexec' was found",
                        "Tkinter is not available for this Python installation",
                        "wimlib-imagex not found",
                        "Verification FAILED",
                        "Drive ejected \u2014 you can unplug it now."):
            with self.subTest(message=message):
                self.assertIn(message, source)
                self.assertIn(message, documentation)


class AboutAndProjectTests(unittest.TestCase):
    def test_project_url_is_https_github(self):
        self.assertRegex(app.PROJECT_URL, r"^https://github\.com/[^/]+/[^/]+$")


if __name__ == "__main__":
    unittest.main()
