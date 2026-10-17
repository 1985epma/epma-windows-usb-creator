"""Documentation and knowledge drift: every fact written in more than one place must agree.

The same facts (the one-line description of the product, how the sudo password is handled,
the ChromeOS Flex sizes, the Python minimum, the critical mount points, the project address,
the exit codes ...) are written in the program, the built-in help, both READMEs, SECURITY.md,
CHANGELOG.md, the Homebrew formula and the CI files. Here they are compared with the constants
and with each other, so a change in one place that forgets the others fails a test.

The tests read files and parse the source; they never touch a device, use sudo or the network.
Several are written to be correct for ANY set of strings (no hard-coded counts), because the
program keeps growing.
"""
import ast
import os
import re
import unittest
from unittest import mock

from tests.helpers import ROOT, app


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def squash(text):
    """Collapse whitespace (and markdown emphasis) so a sentence wrapped over lines still matches."""
    return re.sub(r"\s+", " ", text.replace("**", "").replace("`", ""))


SOURCE = read("win11_usb_creator.py")
TREE = ast.parse(SOURCE)
README = read("README.md")
README_PT = read("README.pt-BR.md")
SECURITY = read("SECURITY.md")
CHANGELOG = read("CHANGELOG.md")
FORMULA = read("Formula", "epma-windows-usb-creator.rb")
HELP = "\n".join(f"{title}\n{body}" for title, body in app.help_sections())
HELP_SECTIONS = dict(app.help_sections())


def module_translatable_literals():
    """The English texts passed to _() / tr() in the module."""
    texts = []
    for node in ast.walk(TREE):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("_", "tr")
                and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            texts.append(node.args[0].value)
    return texts


# ---------------------------------------------------------------------------
# 4. One description of the product
# ---------------------------------------------------------------------------
class TaglineTests(unittest.TestCase):
    KEYWORDS = ("Windows 11", "Linux", "ChromeOS Flex")

    def check(self, where, text):
        for word in self.KEYWORDS:
            self.assertIn(word, text, f"{where} no longer mentions {word}: it describes an older product")

    def test_the_tagline_names_every_supported_image(self):
        self.check("APP_TAGLINE", app.APP_TAGLINE)
        self.assertIn("verified", app.APP_TAGLINE)

    def test_help_about_and_cli_description_use_the_tagline(self):
        self.assertIn(app.APP_TAGLINE, HELP_SECTIONS["About"])
        self.assertIn(app.APP_TAGLINE, app.build_cli_parser().description)

    def test_module_docstring(self):
        self.check("the module docstring", squash(app.__doc__))

    def test_readmes_open_with_the_same_scope(self):
        for name, text in (("README.md", README), ("README.pt-BR.md", README_PT)):
            with self.subTest(readme=name):
                self.check(name, text.split("## ", 1)[0])

    def test_homebrew_formula_description(self):
        match = re.search(r'^\s*desc "([^"]+)"', FORMULA, re.M)
        self.assertIsNotNone(match)
        desc = match.group(1)
        self.check("the Formula desc", desc)
        # Homebrew style (brew audit --strict): under 80 characters, no leading article,
        # no trailing period, starts with a capital letter.
        self.assertLess(len(desc), 80)
        self.assertFalse(desc.endswith("."))
        self.assertNotRegex(desc, r"(?i)^(a|an|the)\s")
        self.assertTrue(desc[0].isupper())

    def test_sbom_description(self):
        text = read(".github", "scripts", "make_sbom.py")
        # the description of the main component (the other "description" keys are system tools)
        match = re.search(r'"name": "epma-usb-creator",\s*"version": clean,\s*"description":\s*"([^"]+)"', text)
        self.assertIsNotNone(match)
        self.check("the SBOM description", match.group(1))


# ---------------------------------------------------------------------------
# 1. The sudo password: every statement must match what PrivilegeHelper really does
# ---------------------------------------------------------------------------
class PasswordWordingTests(unittest.TestCase):
    STALE = (r"asks again", r"asked again", r"ask again", r"pergunta de novo", r"perguntar de novo",
             r"not kept in memory for the whole operation", r"is not held", r"não é guardada")

    def documents(self):
        return {"README.md": README, "README.pt-BR.md": README_PT, "SECURITY.md": SECURITY,
                "CHANGELOG.md": CHANGELOG, "help": HELP, "Formula": FORMULA, "module docstring": app.__doc__}

    def test_no_document_claims_the_old_behaviour(self):
        for name, text in self.documents().items():
            for pattern in self.STALE:
                with self.subTest(document=name, pattern=pattern):
                    self.assertNotRegex(squash(text), "(?i)" + pattern)

    def test_the_fallback_that_keeps_the_password_is_documented(self):
        # The honest statement: normally dropped (sudo's timestamp is used), but when the
        # machine keeps no timestamp the password stays in memory until the operation ends.
        expectations = {
            "README.md": r"only until the operation ends",
            "SECURITY.md": r"only until the operation ends",
            "CHANGELOG.md": r"only until the operation ends",
            "README.pt-BR.md": r"até o fim da operação",
            "help": r"until the operation ends",
        }
        texts = self.documents()
        for name, pattern in expectations.items():
            with self.subTest(document=name):
                self.assertRegex(squash(texts[name]), pattern)

    def test_the_documents_say_it_is_never_logged_or_written_to_disk(self):
        for name in ("README.md", "SECURITY.md"):
            with self.subTest(document=name):
                self.assertRegex(squash(self.documents()[name]), r"(?i)never (written to (any )?(log|disk)|logged)")
        self.assertRegex(squash(README_PT), r"Nunca é registrada em log, gravada em disco")
        self.assertIn("never logged, written to disk or sent anywhere", squash(HELP))

    def test_the_code_really_behaves_that_way(self):
        # Timestamp mode: the password string is dropped. Fallback mode: it is kept until
        # clear_cached_password(). This is what the sentences above describe.
        helper = app.PrivilegeHelper(app=None)
        with mock.patch.object(app.PrivilegeHelper, "_arm_timestamp", return_value=True), \
                mock.patch.object(app.PrivilegeHelper, "_start_keepalive"):
            helper._adopt("secret")
        self.assertIsNone(helper.cached_password)
        self.assertTrue(helper._use_timestamp)

        helper = app.PrivilegeHelper(app=None)
        with mock.patch.object(app.PrivilegeHelper, "_arm_timestamp", return_value=False):
            helper._adopt("secret")
        self.assertEqual(helper.cached_password, "secret")
        self.assertFalse(helper._use_timestamp)
        helper.clear_cached_password()
        self.assertIsNone(helper.cached_password)

    def test_the_password_never_reaches_a_command_line_or_a_log(self):
        # "stdin only" is a claim of every document: no variable named like a password may be
        # part of the argument list (first argument) of a subprocess call.
        checked = 0
        for node in ast.walk(TREE):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("run", "Popen") and node.args):
                checked += 1
                names = {n.id.lower() for n in ast.walk(node.args[0]) if isinstance(n, ast.Name)}
                attrs = {n.attr.lower() for n in ast.walk(node.args[0]) if isinstance(n, ast.Attribute)}
                for name in names | attrs:
                    self.assertNotIn("password", name, f"line {node.lineno}: the password is in an argument list")
                    self.assertNotIn("secret", name, f"line {node.lineno}: the secret is in an argument list")
        self.assertGreater(checked, 5)


# ---------------------------------------------------------------------------
# 2. Numbers in the help that must come from the constants
# ---------------------------------------------------------------------------
class HelpNumbersTests(unittest.TestCase):
    def test_overview_counts_the_four_cards(self):
        overview = HELP_SECTIONS["Overview"]
        self.assertNotIn("Three image types", overview)
        self.assertRegex(overview, r"Four image types")
        for card in ("Google Chrome", "Windows 11", "Linux", "Other ISO"):
            self.assertIn(card, overview)
        self.assertEqual([c for c in app.CARD_ORDER if c != app.CARD_SEED],
                         [app.CARD_CHROME, app.CARD_WINDOWS, app.CARD_LINUX, app.CARD_OTHER])  # the four image types
        # Linux and Other ISO are two cards that write the same way
        self.assertEqual(app.CARD_MODE[app.CARD_LINUX], app.CARD_MODE[app.CARD_OTHER])

    def test_download_retries_come_from_the_constant(self):
        text = squash(HELP_SECTIONS["Getting the image"])
        match = re.search(r"retried automatically \(up to (\d+) retries, (\d+) attempts in all\)", text)
        self.assertIsNotNone(match, "the retry sentence is missing")
        self.assertEqual(int(match.group(2)), app.DOWNLOAD_MAX_ATTEMPTS)
        self.assertEqual(int(match.group(1)), app.DOWNLOAD_MAX_ATTEMPTS - 1)
        self.assertNotRegex(text, r"retried up to \d+ times")
        # and the constant itself matches the backoff table: one wait per retry
        self.assertEqual(len(app.DOWNLOAD_BACKOFF_SECONDS), app.DOWNLOAD_MAX_ATTEMPTS - 1)

    def test_audit_log_rotation_comes_from_the_constants(self):
        megabytes = f"{app.AUDIT_LOG_MAX_BYTES / 1_000_000:g}"
        old_files = str(app.AUDIT_LOG_BACKUPS)
        pattern = re.compile(r"(\d+(?:\.\d+)?) MB(?: \(|,)? ?(?:keeping )?(\d+) (?:older|old) files")
        for name, text in (("help", HELP), ("SECURITY.md", SECURITY), ("CHANGELOG.md", CHANGELOG)):
            with self.subTest(document=name):
                match = pattern.search(squash(text))
                self.assertIsNotNone(match, f"{name} does not state the audit log rotation")
                self.assertEqual((match.group(1), match.group(2)), (megabytes, old_files))

    def test_every_critical_mount_point_is_documented(self):
        # CRITICAL_MOUNTPOINTS has more entries than the old lists (/boot/efi): the help,
        # both READMEs and SECURITY.md must name each one.
        self.assertGreaterEqual(len(app.CRITICAL_MOUNTPOINTS), 6)
        for mount in app.CRITICAL_MOUNTPOINTS:
            self.assertIn(mount, HELP_SECTIONS["Safety"], f"help Safety does not name {mount}")
            for name, text in (("README.md", README), ("README.pt-BR.md", README_PT), ("SECURITY.md", SECURITY)):
                with self.subTest(document=name, mount=mount):
                    self.assertIn(f"`{mount}`", text)
        # the code also hides anything under /boot, and the documents say so
        self.assertIn('mp.startswith("/boot")', SOURCE)
        for text in (HELP_SECTIONS["Safety"], README, SECURITY, README_PT):
            self.assertRegex(squash(text), r"(anything under|qualquer coisa sob)")

    def test_tk_hint_is_one_and_the_same_everywhere(self):
        formula_version = re.search(r'depends_on "python-tk@(\d+\.\d+)"', FORMULA).group(1)
        pinned = re.search(r'depends_on "python@(\d+\.\d+)"', FORMULA).group(1)
        self.assertEqual(formula_version, pinned, "the Homebrew formula pins python-tk and python differently")
        documents = {"module": SOURCE, "README.md": README, "README.pt-BR.md": README_PT,
                     "help": HELP, "requirements.txt": read("requirements.txt")}
        for name, text in documents.items():
            for version in re.findall(r"python-tk@(\d+\.\d+)", text):
                with self.subTest(document=name):
                    self.assertEqual(version, formula_version, f"{name} suggests python-tk@{version}")
        # wherever a version is spelled out, the text also says it must match the user's Python
        for name, text in (("README.md", README), ("help", HELP)):
            with self.subTest(document=name):
                self.assertRegex(squash(text), r"(?i)python-tk.{0,40}(matches?|matching) your Python")


class StaleWordsTests(unittest.TestCase):
    def test_no_tabs_in_the_documents(self):
        # The window has four cards on one page, not tabs.
        for name, text in (("README.md", README), ("help", HELP)):
            with self.subTest(document=name):
                self.assertNotRegex(text, r"(?i)\btabs?\b")
        self.assertNotRegex(README_PT, r"(?i)\babas?\b")
        self.assertNotRegex(read("CHANGELOG.md").split("## [1.0.0]")[0].replace("replace the three tabs", ""),
                            r"(?i)\btabs?\b")

    def test_new_behaviours_are_mentioned(self):
        # Closing the window during a write asks first; dependencies are checked before erasing.
        self.assertIn("Closing the window", squash(HELP))
        self.assertIn("Closing the window", squash(README))
        self.assertIn("Closing the window", squash(SECURITY))
        self.assertIn("Fechar a janela", README_PT)
        for text in (HELP, README, SECURITY):
            self.assertRegex(squash(text), r"(?i)(missing (system )?(tools|dependencies)|dependencies).{0,200}"
                                          r"before (anything|the drive)")
        self.assertRegex(squash(README_PT), r"ausentes são detectadas \*?\*?antes\*?\*? de apagar")


# ---------------------------------------------------------------------------
# 5. Release tripwires and hard-coded counts
# ---------------------------------------------------------------------------
class ReleaseTests(unittest.TestCase):
    def test_changelog_has_the_current_version(self):
        # THE one place that fails on a version bump: update the CHANGELOG (and the Formula
        # after the release) together with __version__.
        version = re.escape(app.__version__)
        self.assertRegex(CHANGELOG, rf"(?m)^## \[{version}\]( - .+)?$")
        self.assertRegex(CHANGELOG, rf"(?m)^\[{version}\]: https://github\.com/")

    def test_release_notes_can_be_extracted(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "changelog_section", os.path.join(ROOT, ".github", "scripts", "changelog_section.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        notes = module.extract(CHANGELOG, "v" + app.__version__)
        self.assertGreater(len(notes), 200, "the release workflow would publish empty notes")

    def test_an_unreleased_version_is_marked_as_such(self):
        heading = re.search(rf"(?m)^## \[{re.escape(app.__version__)}\] - (.+)$", CHANGELOG).group(1)
        self.assertRegex(heading, r"^(unreleased|\d{4}-\d{2}-\d{2})$")

    def test_no_check_counts_are_hard_coded(self):
        # "27 proteções", "44 verificações" ... went stale every time a check was added.
        files = ["verificar.py", "output/auditoria/README.md", "README.md", "README.pt-BR.md", "SECURITY.md",
                 ".github/workflows/ci.yml", ".github/workflows/security.yml", "output/auditoria/guard_seguranca.py",
                 "output/auditoria/testes_validacao.py"]
        pattern = re.compile(r"(?i)(?<![-\d.])\b\d+\s+(prote[cç][õo]es|verifica[cç][õo]es|testes automatizados|audit fixes|"
                             r"regress[õo]es simuladas|correç[õo]es da auditoria)")
        for name in files:
            with self.subTest(file=name):
                self.assertIsNone(pattern.search(read(*name.split("/"))),
                                  f"{name} hard-codes a number of checks; say 'the checks' instead")

    def test_stdlib_list_in_requirements_matches_the_imports(self):
        block = read("requirements.txt").split("padrão do Python:")[1].split("# Requisito")[0]
        listed = {tok.split(".")[0] for tok in re.findall(r"[a-z][a-z0-9_.]*", block.replace("#", " "))
                  if tok not in ("e",)}
        imported = set()
        for node in ast.walk(TREE):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported.add(node.module.split(".")[0])
        self.assertEqual(sorted(imported - listed), [], "imported but not listed in requirements.txt")


# ---------------------------------------------------------------------------
# 6. Dead translations
# ---------------------------------------------------------------------------
# Keys that are translated through a variable at run time, so no literal call shows them:
#   * "Error" / "Unexpected error": the title passed to App._report_error, which runs
#     messagebox.showerror(_(title), ...). The calls that name them are `self.after(0,
#     self._report_error, "Error", ...)`, found by the scan below too; they are listed here
#     explicitly so removing the call site does not silently orphan them.
#   * the engine's stage names ("Preparing the drive...", ...) reach App._on_create_progress as
#     text and are translated by `_(text)`; they are found as the literal stage argument of
#     the progress(...) / report(...) calls.
DYNAMICALLY_TRANSLATED = frozenset({"Error", "Unexpected error", "Preparing the drive..."})
USAGE_CALL_NAMES = {"_", "tr", "progress", "report", "_report_error", "after"}


def used_translation_keys():
    used = set(DYNAMICALLY_TRANSLATED)
    for node in ast.walk(TREE):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
        if name not in USAGE_CALL_NAMES and "progress" not in name.lower():
            continue
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                used.add(arg.value)
    return used


class DeadTranslationTests(unittest.TestCase):
    def test_no_pt_br_key_is_unused(self):
        used = used_translation_keys()
        self.assertGreater(len(used), 50, "the scan found suspiciously few translated texts")
        dead = sorted(key[:80] for key in app.PT_BR if key not in used)
        self.assertEqual(dead, [], "PT_BR keys that no _() call, stage literal or dynamic title uses: "
                                   "delete them (or fix the text that no longer matches)")

    def test_every_literal_still_has_its_translation(self):
        # the reverse direction (also in test_i18n): nothing passed to _() lacks an entry
        missing = sorted(t[:80] for t in module_translatable_literals() if t not in app.PT_BR)
        self.assertEqual(missing, [])


# ---------------------------------------------------------------------------
# 7. The two READMEs have the same structure
# ---------------------------------------------------------------------------
def outline(text):
    """(heading levels, tables as (rows, columns), number of code blocks) of a markdown file."""
    headings, tables, blocks = [], [], 0
    in_code, table = False, []
    for line in text.splitlines():
        if line.startswith("```"):
            in_code = not in_code
            blocks += 0 if in_code else 1
            continue
        if in_code:
            continue
        if line.startswith("|"):
            table.append(line)
            continue
        if table:
            tables.append((len(table), table[0].count("|") - 1))
            table = []
        match = re.match(r"(#{1,6}) ", line)
        if match:
            headings.append(len(match.group(1)))
    if table:
        tables.append((len(table), table[0].count("|") - 1))
    return headings, tables, blocks


class ReadmeParityTests(unittest.TestCase):
    def test_same_headings_tables_and_code_blocks(self):
        en, pt = outline(README), outline(README_PT)
        self.assertEqual(en[0], pt[0], "README.pt-BR.md has different ## / ### headings than README.md")
        self.assertEqual(en[1], pt[1], "the tables differ (rows, columns)")
        self.assertEqual(en[2], pt[2], "the number of code blocks differs")
        self.assertGreater(len(en[0]), 20)
        self.assertEqual(len(en[1]), 3)

    def test_table_of_contents_links_exist(self):
        for name, text in (("README.md", README), ("README.pt-BR.md", README_PT)):
            headings = {self.anchor(m) for m in re.findall(r"(?m)^#{2,3} (.+)$", text)}
            for link in re.findall(r"\]\(#([^)]+)\)", text):
                with self.subTest(readme=name, anchor=link):
                    self.assertIn(link, headings)

    @staticmethod
    def anchor(heading):
        slug = re.sub(r"[^\w\- ]", "", heading.lower().replace("`", "")).strip().replace(" ", "-")
        return slug

    def test_readmes_link_each_other_and_the_same_files(self):
        self.assertIn("README.pt-BR.md", README)
        self.assertIn("README.md", README_PT)
        local = re.compile(r"\]\(((?!https?:|#)[^)]+)\)")
        for name, text in (("README.md", README), ("README.pt-BR.md", README_PT)):
            for target in local.findall(text):
                with self.subTest(readme=name, link=target):
                    self.assertTrue(os.path.exists(os.path.join(ROOT, target.split("#")[0])), target)


# ---------------------------------------------------------------------------
# 8. Facts written in 20+ places (ChromeOS Flex and friends)
# ---------------------------------------------------------------------------
def gb(value):
    return float(value.replace(",", "."))


class ConstantsInTextTests(unittest.TestCase):
    def corpus(self):
        """Every text where a fact may be written: the module (code, _() texts, PT_BR) and the documents."""
        return {"module": SOURCE, "help": HELP, "README.md": README, "README.pt-BR.md": README_PT,
                "SECURITY.md": SECURITY, "CHANGELOG.md": CHANGELOG}

    def test_usb_minimum_for_chromeos_flex(self):
        # Google asks for "16 GB or larger"; a stick sold as 16 GB holds ~15.5e9 bytes, which is
        # why the threshold in bytes is lower than 16e9. The marketed size is the smallest
        # standard size that is not below the threshold.
        marketed = next(s for s in (4, 8, 16, 32, 64, 128, 256) if s * 10 ** 9 >= app.CHROMEOS_MIN_USB_BYTES)
        self.assertGreater(app.CHROMEOS_MIN_USB_BYTES, marketed * 10 ** 9 * 0.85,
                           "the threshold is far below the marketed size: is 15 GB still right?")
        found = 0
        for name, text in self.corpus().items():
            for value in re.findall(r"(\d+) GB (?:or larger|ou maior)", squash(text)):
                found += 1
                with self.subTest(document=name):
                    self.assertEqual(int(value), marketed, f"{name} says {value} GB; the code says {marketed} GB")
        self.assertGreater(found, 8, "the scan found too few mentions of the drive minimum")
        for text in module_translatable_literals():
            for value in re.findall(r"(\d+) GB or larger", text):
                self.assertEqual(int(value), marketed, text[:60])

    def test_large_drive_threshold(self):
        limit = app.LARGE_DISK_BYTES // 1024 ** 3
        found = 0
        pattern = r"(?i)(?:drives?|disks?|discos?)[^.;]{0,40}?(?:larger than|over|maior que|>)\s*(\d+) GB"
        for name, text in self.corpus().items():
            for value in re.findall(pattern, squash(text)):
                found += 1
                with self.subTest(document=name):
                    self.assertEqual(int(value), limit, f"{name} says {value} GB for a large drive")
        self.assertGreater(found, 4)

    def test_substantial_use_and_volume_thresholds_in_help(self):
        text = squash(HELP_SECTIONS["The drive and the Create button"])
        self.assertIn(f"{app.SUBSTANTIAL_USED_BYTES // 1024 ** 3} GB or more in use", text)
        self.assertIn(f"{app.MANY_VOLUMES} or more volumes", text)

    def test_download_and_image_sizes_match_the_measured_constants(self):
        match = re.search(r"the ZIP is about ([\d.]+) GB and the image inside it about ([\d.]+) GB", SOURCE)
        self.assertIsNotNone(match, "the comment with the measured sizes next to CHROMEOS_FLEX_FREE_BYTES is gone")
        zip_gb, image_gb = gb(match.group(1)), gb(match.group(2))
        free_gb = app.CHROMEOS_FLEX_FREE_BYTES / 10 ** 9
        # both files are on disk at once, so the warning threshold must cover their sum
        self.assertGreaterEqual(free_gb, zip_gb + image_gb)
        self.assertLessEqual(free_gb, (zip_gb + image_gb) * 1.5, "the free-space threshold is far too generous")
        self.assertLess(app.CHROMEOS_FLEX_FREE_BYTES, app.DISK_IMAGE_MAX_BYTES)
        self.assertLess(image_gb * 10 ** 9, app.DISK_IMAGE_MAX_BYTES)
        # every "about X GB" the program or the help states is one of the two measured sizes
        texts = {"help": squash(HELP_SECTIONS["ChromeOS Flex"]), "module": " ".join(module_translatable_literals())}
        seen = 0
        for name, text in texts.items():
            for value in re.findall(r"about ([\d.]+) GB", text):
                seen += 1
                with self.subTest(document=name):
                    self.assertIn(gb(value), (zip_gb, image_gb))
            for value in re.findall(r"(?:roughly|about) (\d+) GB free", text):
                self.assertEqual(int(value), round(free_gb))
        self.assertGreaterEqual(seen, 3)
        # the Portuguese text uses a decimal comma
        pt = " ".join(v for k, v in app.PT_BR.items() if "Not much free space" not in k)
        for value in re.findall(r"cerca de ([\d,]+) GB", pt):
            self.assertIn(gb(value), (zip_gb, image_gb))

    def test_python_minimum_is_the_same_everywhere(self):
        pyproject = read("pyproject.toml")
        target = re.search(r'target-version = "py(\d)(\d+)"', pyproject)
        minimum = f"{target.group(1)}.{target.group(2)}"
        checks = {
            "README.md badge": (README, r"python-(\d+\.\d+)%2B"),
            "README.pt-BR.md badge": (README_PT, r"python-(\d+\.\d+)%2B"),
            "README.md text": (README, r"Python \*\*(\d+\.\d+) or newer"),
            "README.pt-BR.md text": (README_PT, r"Python \*\*(\d+\.\d+) ou mais novo"),
            "CHANGELOG.md": (CHANGELOG, r"Minimum supported Python is now (\d+\.\d+)"),
            "requirements.txt": (read("requirements.txt"), r"Python (\d+\.\d+) ou superior"),
            "pyproject.toml comment": (pyproject, r"Python mínimo suportado: (\d+\.\d+)"),
            "make_sbom.py": (read(".github", "scripts", "make_sbom.py"), r'"min": "(\d+\.\d+)"'),
            "ci.yml matrix": (read(".github", "workflows", "ci.yml"), r"python: \['(\d+\.\d+)'"),
            "ci.yml comment": (read(".github", "workflows", "ci.yml"), r"Python (\d+\.\d+)–3\.\d+"),
            "verifica_dependencias.py": (read("output", "auditoria", "verifica_dependencias.py"),
                                         r"sys\.version_info < \((\d+), (\d+)\)"),
        }
        for name, (text, pattern) in checks.items():
            with self.subTest(source=name):
                match = re.search(pattern, text)
                self.assertIsNotNone(match, f"{name}: the Python minimum is not stated")
                value = ".".join(match.groups())
                self.assertEqual(value, minimum, f"{name} says Python {value}; pyproject.toml says {minimum}")

    def test_project_address_is_the_same_everywhere(self):
        slug = app.PROJECT_URL.split("github.com/")[1]
        owner, repo = slug.split("/")
        self.assertIn(f'homepage "{app.PROJECT_URL}"', FORMULA)
        self.assertIn(f'head "{app.PROJECT_URL}.git"', FORMULA)
        self.assertIn(f'url "{app.PROJECT_URL}/archive/refs/tags/', FORMULA)
        self.assertIn(f'DEFAULT_REPO = "{slug}"', read(".github", "scripts", "make_sbom.py"))
        link = re.compile(r"github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)")
        files = {"README.md": README, "README.pt-BR.md": README_PT, "SECURITY.md": SECURITY,
                 "CHANGELOG.md": CHANGELOG, "Formula": FORMULA, "module": SOURCE,
                 "update-formula.sh": read("Formula", "update-formula.sh")}
        checked = 0
        for name, text in files.items():
            for found_owner, found_repo in link.findall(text):
                found_repo = found_repo.removesuffix(".git").rstrip(".")
                if found_repo.lower().startswith("epma-"):
                    checked += 1
                    with self.subTest(file=name, link=f"{found_owner}/{found_repo}"):
                        self.assertEqual((found_owner, found_repo), (owner, repo))
        self.assertGreater(checked, 8)
        for name, text in files.items():
            for target in re.findall(r"--repo (\S+)", text):
                with self.subTest(file=name, repo=target):
                    self.assertEqual(target, slug)

    def test_homebrew_tap_name_is_consistent(self):
        tap = f"{app.PROJECT_URL.split('/')[3]}/tap"
        for name, text in (("README.md", README), ("README.pt-BR.md", README_PT), ("Formula", FORMULA)):
            with self.subTest(file=name):
                self.assertIn(f"brew tap {tap}", text)


class ChromeOSFactsTests(unittest.TestCase):
    def test_google_requirements_are_stated_alike(self):
        # Computer requirements Google lists: 4 GB of RAM, 16 GB of storage.
        for name, text in (("help", squash(HELP_SECTIONS["ChromeOS Flex"])), ("README.md", squash(README))):
            with self.subTest(document=name):
                self.assertRegex(text, r"4 GB of RAM")
                self.assertRegex(text, r"16 GB of internal storage")
        self.assertIn("4 GB de RAM", README_PT)
        self.assertIn("16 GB de armazenamento interno", README_PT)

    def test_urls_in_the_documents_are_the_constants(self):
        for url in (app.CHROMEOS_FLEX_GUIDE_URL, app.CHROMEOS_FLEX_REQUIREMENTS_URL):
            for name, text in (("README.md", README), ("README.pt-BR.md", README_PT), ("help", HELP)):
                with self.subTest(document=name, url=url):
                    self.assertIn(url, text)
        self.assertIn(app.CHROMEOS_FLEX_URL, SECURITY)
        self.assertIn(app.CHROMEOS_FLEX_HOSTS[0], README)


if __name__ == "__main__":
    unittest.main()


class ScreenshotTests(unittest.TestCase):
    """Both READMEs show a picture of the window; the file must exist so the link never breaks."""

    def test_the_readmes_point_to_an_existing_screenshot(self):
        import os
        import re
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for name in ("README.md", "README.pt-BR.md"):
            with self.subTest(readme=name):
                with open(os.path.join(root, name), encoding="utf-8") as fh:
                    text = fh.read()
                links = re.findall(r'<img[^>]+src="([^"]+)"', text)
                self.assertIn("docs/images/interface.png", links)
                for link in links:
                    path = os.path.join(root, link)
                    self.assertTrue(os.path.isfile(path), link)
                    with open(path, "rb") as image:
                        self.assertEqual(image.read(8), b"\x89PNG\r\n\x1a\n", f"{link} is not a PNG")
                    self.assertLess(os.path.getsize(path), 1_500_000, f"{link} is too big for a README")
                    # the screenshot must not carry a personal home folder
                self.assertNotIn("alt=\"\"", text)

