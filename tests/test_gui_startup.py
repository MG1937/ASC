"""Exercise CLI GUI startup without requiring a desktop or a Tk installation."""
import builtins
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from droidasc import cli as main


class GuiStartupTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.apk = Path(directory.name) / 'sample.apk'
        self.apk.touch()
        self.gui = types.ModuleType('droidasc.asc_client.gui.app')
        self.gui.launch_gui = Mock()
        self.modules = {
            'tkinter': types.ModuleType('tkinter'),
            'droidasc.asc_client.gui.app': self.gui,
        }

    def test_macos_gui_launches_in_foreground(self):
        with patch.dict(sys.modules, self.modules), \
                patch.object(sys, 'platform', 'darwin'), \
                patch.object(sys, 'argv', ['main.py', str(self.apk), '--gui', '--threads', '3']), \
                patch.object(main.subprocess, 'Popen') as popen:
            main.main()
            popen.assert_not_called()
            self.gui.launch_gui.assert_called_once_with(
                str(self.apk), max_workers=3, debug=False)

    def test_missing_tk_is_reported_before_spawning(self):
        original_import = builtins.__import__
        for module in ('tkinter', '_tkinter'):
            def missing_tk(name, *args, **kwargs):
                if name == 'tkinter':
                    raise ModuleNotFoundError(f"No module named '{module}'", name=module)
                return original_import(name, *args, **kwargs)

            with self.subTest(module=module), patch('builtins.__import__', side_effect=missing_tk), \
                    patch.object(sys, 'platform', 'linux'), \
                    patch.object(sys, 'argv', ['main.py', str(self.apk), '--gui']), \
                    patch.object(main.subprocess, 'Popen') as popen, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr, \
                    self.assertRaises(SystemExit) as exit_result:
                main.main()
            self.assertEqual(exit_result.exception.code, 1)
            self.assertIn('GUI requires tkinter', stderr.getvalue())
            self.assertIn(sys.executable, stderr.getvalue())
            self.assertNotIn('Traceback', stderr.getvalue())
            popen.assert_not_called()

    def test_initialization_errors_are_visible_and_debug_keeps_traceback(self):
        self.gui.launch_gui.side_effect = RuntimeError('Tk initialization failed')
        for debug in (False, True):
            argv = ['main.py', str(self.apk), '--gui'] + (['--debug'] if debug else [])
            with self.subTest(debug=debug), patch.dict(sys.modules, self.modules), \
                    patch.object(sys, 'platform', 'darwin'), patch.object(sys, 'argv', argv), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr, \
                    self.assertRaises(SystemExit) as exit_result:
                main.main()
            self.assertEqual(exit_result.exception.code, 1)
            self.assertIn('Tk initialization failed', stderr.getvalue())
            self.assertEqual('Traceback' in stderr.getvalue(), debug)

    def test_detached_launch_preserves_caller_path_and_stderr(self):
        # Pass an absolute APK path to the detached module entry point.
        with patch.dict(sys.modules, self.modules), patch.object(sys, 'platform', 'linux'), \
                patch.object(main.subprocess, 'Popen') as popen:
            main._run_gui([os.path.relpath(self.apk), '--gui'])
            command = popen.call_args.args[0]
            self.assertEqual(command[:3], [sys.executable, '-m', 'droidasc'])
            self.assertEqual(command[3], str(self.apk))
            self.assertIn('--gui-foreground', command)
            self.assertIsNone(popen.call_args.kwargs['stderr'])
            self.gui.launch_gui.assert_not_called()

    def test_explicit_foreground_and_debug_do_not_spawn(self):
        for option in ('--gui-foreground', '--debug'):
            with self.subTest(option=option), patch.dict(sys.modules, self.modules), \
                    patch.object(sys, 'platform', 'linux'), \
                    patch.object(main.subprocess, 'Popen') as popen:
                main._run_gui([str(self.apk), '--gui', option])
                popen.assert_not_called()
                self.gui.launch_gui.assert_called_once_with(
                    str(self.apk), max_workers=8, debug=option == '--debug')
                self.gui.launch_gui.reset_mock()

    def test_missing_apk_is_reported_without_launch(self):
        with patch.object(sys, 'argv', ['main.py', str(self.apk) + '.missing', '--gui']), \
                patch.object(main.subprocess, 'Popen') as popen, \
                contextlib.redirect_stderr(io.StringIO()) as stderr, \
                self.assertRaises(SystemExit) as exit_result:
            main.main()
        self.assertEqual(exit_result.exception.code, 2)
        self.assertIn('APK file not found', stderr.getvalue())
        popen.assert_not_called()

    def test_gui_help_does_not_require_tk(self):
        with patch.dict(sys.modules, {'tkinter': None}), \
                patch.object(sys, 'argv', ['main.py', '--gui', '--help']), \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                self.assertRaises(SystemExit) as exit_result:
            main.main()
        self.assertEqual(exit_result.exception.code, 0)
        self.assertIn('--gui', stdout.getvalue())
