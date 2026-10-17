"""Tests for the GUI translation layer (English by default, Brazilian Portuguese on request).

No Tk is needed: the language lookup, the PT_BR dictionary and the source of the module are
checked directly. A text that was wrapped in _() but forgotten in PT_BR fails here instead of
silently showing English to a Portuguese user.
"""
import ast
import os
import re
import string
import unittest
from unittest import mock

from tests.helpers import ROOT, app

SOURCE_PATH = os.path.join(ROOT, "win11_usb_creator.py")
PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}")
TRANSLATE_NAMES = {"_", "tr"}


def module_tree():
    with open(SOURCE_PATH, encoding="utf-8") as fh:
        return ast.parse(fh.read())


def placeholders(text):
    return set(PLACEHOLDER_RE.findall(text))


class DetectLanguageTests(unittest.TestCase):
    def test_default_is_english(self):
        self.assertEqual(app.detect_language({}), "en")

    def test_empty_values_are_english(self):
        env = {"EPMA_LANG": "", "LC_ALL": "", "LC_MESSAGES": "", "LANG": ""}
        self.assertEqual(app.detect_language(env), "en")

    def test_the_system_locale_is_never_used(self):
        # The interface is always US English; a Portuguese system must not change it.
        for env in ({"LANG": "pt_BR.UTF-8"}, {"LC_ALL": "pt_BR"}, {"LC_MESSAGES": "pt_PT"}, {"LANG": "pt"},
                    {"LANG": "pt_BR.UTF-8", "LC_ALL": "pt_BR.UTF-8", "LC_MESSAGES": "pt_BR.UTF-8"},
                    {"LANG": "en_US.UTF-8"}, {"LANG": "C"}, {"LANG": "de_DE.UTF-8"}):
            with self.subTest(env=env):
                self.assertEqual(app.detect_language(env), "en")

    def test_epma_lang_values(self):
        for value in ("pt", "pt-BR", "PT-br", "pt_BR", " pt "):
            with self.subTest(value=value):
                self.assertEqual(app.detect_language({"EPMA_LANG": value}), "pt")
        for value in ("en", "EN", "en-US", "fr", "xx"):
            with self.subTest(value=value):
                self.assertEqual(app.detect_language({"EPMA_LANG": value}), "en")

    def test_epma_lang_is_the_only_way_to_get_portuguese(self):
        self.assertEqual(app.detect_language({"EPMA_LANG": "en", "LANG": "pt_BR.UTF-8", "LC_ALL": "pt_BR"}), "en")
        self.assertEqual(app.detect_language({"EPMA_LANG": "pt", "LANG": "en_US.UTF-8", "LC_ALL": "C"}), "pt")

    def test_default_environment_is_os_environ(self):
        with mock.patch.dict(os.environ, {"EPMA_LANG": "pt"}):
            self.assertEqual(app.detect_language(), "pt")
        with mock.patch.dict(os.environ, {"EPMA_LANG": "en"}):
            self.assertEqual(app.detect_language(), "en")

    def test_the_test_suite_runs_in_english(self):
        self.assertEqual(app.ACTIVE_LANGUAGE, "en")


class TranslateTests(unittest.TestCase):
    def test_english_returns_the_text_unchanged(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "en"):
            self.assertEqual(app._("Cancel"), "Cancel")
            self.assertEqual(app._("Writing the image..."), "Writing the image...")

    def test_portuguese_returns_the_translation(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            self.assertEqual(app._("Cancel"), "Cancelar")
            self.assertEqual(app._("Writing the image..."), "Gravando a imagem...")

    def test_unknown_text_falls_back_to_english(self):
        for lang in ("en", "pt"):
            with self.subTest(lang=lang), mock.patch.object(app, "ACTIVE_LANGUAGE", lang):
                self.assertEqual(app._("Text that nobody translated {x}"), "Text that nobody translated {x}")
                self.assertEqual(app._(""), "")

    def test_format_after_translating(self):
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            self.assertEqual(app._("Selected ISO: {path}").format(path="/x.iso"), "ISO selecionada: /x.iso")
            self.assertEqual(app._("Could not list disks: {error}").format(error="x"),
                             "Não foi possível listar os discos: x")
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "en"):
            self.assertEqual(app._("Selected ISO: {path}").format(path="/x.iso"), "Selected ISO: /x.iso")

    def test_tr_is_the_same_function(self):
        self.assertIs(app.tr, app._)

    def test_same_input_gives_the_same_output(self):
        # _on_create_progress compares stage texts to notice a new stage.
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            self.assertEqual(app._("Copying files..."), app._("Copying files..."))
            self.assertNotEqual(app._("Copying files..."), app._("Writing the image..."))

    def test_engine_text_stays_english_by_default(self):
        disk = {"id": "disk9", "size": 8 * 1024 ** 3, "model": "Fake Stick",
                "volumes": [{"name": "Backup", "filesystem": "HFS+", "size": 1024 ** 3, "used": None,
                             "mountpoint": None}]}
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "pt"):
            plain = app.describe_disk_for_confirmation(disk)
            self.assertIn("Contents that will be DESTROYED:", plain)
            self.assertIn("not mounted, usage unknown", plain)
            translated = app.describe_disk_for_confirmation(disk, translate=True)
            self.assertIn("Conteúdo que será DESTRUÍDO:", translated)
            self.assertIn("não montado, uso desconhecido", translated)
            self.assertNotIn("Contents that will be DESTROYED:", translated)
            self.assertEqual(app.assess_disk_risk(disk)[0], app.assess_disk_risk(disk, translate=True)[0])
            self.assertIn("suggest personal data or backups", " ".join(app.assess_disk_risk(disk)[1]))
            self.assertIn("sugere(m) dados pessoais", " ".join(app.assess_disk_risk(disk, translate=True)[1]))

    def test_translate_flag_in_english_is_identical(self):
        disk = {"id": "disk9", "size": 512 * 1024 ** 3, "model": "My Passport", "volumes": None}
        with mock.patch.object(app, "ACTIVE_LANGUAGE", "en"):
            self.assertEqual(app.describe_disk_for_confirmation(disk),
                             app.describe_disk_for_confirmation(disk, translate=True))
            self.assertEqual(app.assess_disk_risk(disk), app.assess_disk_risk(disk, translate=True))


class DictionaryTests(unittest.TestCase):
    def test_dictionary_is_not_empty_and_entries_are_filled(self):
        self.assertGreater(len(app.PT_BR), 50)
        for key, value in app.PT_BR.items():
            with self.subTest(key=key[:60]):
                self.assertIsInstance(key, str)
                self.assertIsInstance(value, str)
                self.assertTrue(key.strip(), "empty key")
                self.assertTrue(value.strip(), "empty translation")

    def test_placeholders_match_the_english_text(self):
        for key, value in app.PT_BR.items():
            with self.subTest(key=key[:60]):
                self.assertEqual(placeholders(key), placeholders(value))

    def test_translations_format_like_the_english_text(self):
        # Catches stray or unbalanced braces: both must accept the same arguments.
        for key, value in app.PT_BR.items():
            with self.subTest(key=key[:60]):
                names = {name for _lit, name, _spec, _conv in string.Formatter().parse(key) if name}
                args = dict.fromkeys(names, 1)
                key.format(**args)
                value.format(**args)

    def test_no_duplicate_keys_in_the_source(self):
        for node in ast.walk(module_tree()):
            if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "PT_BR" for t in node.targets):
                keys = [k.value for k in node.value.keys]
                dups = sorted({k for k in keys if keys.count(k) > 1})
                self.assertEqual(dups, [], "duplicate keys in PT_BR")
                self.assertEqual(len(keys), len(app.PT_BR))
                return
        self.fail("PT_BR assignment not found")

    def test_translation_is_really_different_text_for_prose(self):
        # Most entries must differ from the English key; the few that may be equal are names.
        same = [k for k, v in app.PT_BR.items() if k == v]
        self.assertLessEqual(sorted(same), ["OK", "Windows 11"])


class SourceCoverageTests(unittest.TestCase):
    """Every text the code passes to _()/tr() must have an entry in PT_BR."""

    @classmethod
    def setUpClass(cls):
        cls.tree = module_tree()

    def translate_calls(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in TRANSLATE_NAMES:
                yield node

    def test_every_literal_passed_to_translate_is_in_the_dictionary(self):
        found = 0
        missing = []
        for call in self.translate_calls():
            self.assertEqual(len(call.args), 1, f"line {call.lineno}: _() takes exactly one argument")
            arg = call.args[0]
            self.assertNotIsInstance(arg, ast.JoinedStr,
                                     f"line {call.lineno}: an f-string cannot be translated; use _().format()")
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                found += 1
                if arg.value not in app.PT_BR:
                    missing.append(f"line {call.lineno}: {arg.value[:70]!r}")
        self.assertGreater(found, 50, "the scan found suspiciously few translatable texts")
        self.assertEqual(missing, [], "texts passed to _() without a PT_BR entry")

    def test_only_known_variables_are_translated_dynamically(self):
        # _(variable) is invisible to the check above, so each such use is listed here:
        # `text` in _on_create_progress (engine stage names, covered by the next test),
        # `title` in _report_error (literals checked below), and `_text_for`'s own return.
        allowed = {"text", "title"}
        dynamic = []
        for call in self.translate_calls():
            arg = call.args[0]
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                dynamic.append(ast.unparse(arg))
        self.assertTrue(set(dynamic) <= allowed, f"unexpected dynamic translation: {sorted(set(dynamic) - allowed)}")

    def test_progress_stage_texts_are_translated(self):
        # The engine reports stages in English: progress(done, total, "Text") and report(done, "Text").
        stages = {"Preparing the drive..."}
        for node in ast.walk(self.tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                continue
            if node.func.id == "progress" and len(node.args) == 3:
                arg = node.args[2]
            elif node.func.id == "report" and len(node.args) == 2:
                arg = node.args[1]
            else:
                continue
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                stages.add(arg.value)
        # CLI-only stage name, never shown by the GUI.
        stages.discard("Computing SHA-256...")
        stages.discard("Downloading")  # command line only (fetch-chromeos)
        stages.discard("Extracting")
        self.assertGreaterEqual(len(stages), 8)
        missing = sorted(s for s in stages if s not in app.PT_BR)
        self.assertEqual(missing, [], "progress stage texts without a PT_BR entry")

    def test_report_error_titles_are_translated(self):
        titles = set()
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "_report_error" and node.args:
                arg = node.args[0]                      # self._report_error("Title", ...)
            elif (isinstance(func, ast.Attribute) and func.attr == "after" and len(node.args) >= 3
                  and isinstance(node.args[1], ast.Attribute) and node.args[1].attr == "_report_error"):
                arg = node.args[2]                      # self.after(0, self._report_error, "Title", ...)
            else:
                continue
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                titles.add(arg.value)
        self.assertTrue({"Error", "Unexpected error"} <= titles)
        self.assertEqual(sorted(t for t in titles if t not in app.PT_BR), [])

    def test_messagebox_calls_use_translated_titles(self):
        # A messagebox title given as a bare literal would stay English in Portuguese.
        bare = []
        for node in ast.walk(self.tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "messagebox"
                    and node.args and isinstance(node.args[0], ast.Constant)):
                bare.append(f"line {node.lineno}: {node.args[0].value!r}")
        self.assertEqual(bare, [], "messagebox titles that bypass _()")


if __name__ == "__main__":
    unittest.main()
