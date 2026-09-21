import unittest
from types import SimpleNamespace

from droidasc.asc_client.gui.app import AscGuiApp
from droidasc.asc_client.gui.runtime import build_find_query
from droidasc.asc_client.gui.text_utils import decode_java_unicode_escapes_with_ranges
from droidasc.asc_client.gui.widgets import EditorTab
from droidasc.asc_client.gui.source_edit import (
    find_member_declaration,
    linkable_member_spans,
    member_reference_at_offset,
    remap_ranges_after_replacements,
)
from droidasc.asc_core.findrefs.findrefs_manager import FindRefManager
from droidasc.asc_core.utils.decompiler import _source_with_member_references
from droidasc.asc_core.utils.tinydex import DEX


class _Value:
    def __init__(self, value=None):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class _NavigationText:
    def __init__(self, click_index="1.0"):
        self.click_index = click_index
        self.insert = "1.0"
        self.seen = []
        self.tags = []

    def index(self, value):
        if str(value).startswith("@"):
            return self.click_index
        if value == "insert":
            return self.insert
        return value

    def mark_set(self, _mark, value):
        self.insert = value

    def see(self, value):
        self.seen.append(value)

    def yview(self):
        return (0.5, 0.75)

    def tag_remove(self, name, start, end):
        self.tags.append(("remove", name, start, end))

    def tag_raise(self, name):
        self.tags.append(("raise", name))


def _text_index(text, offset):
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset) + 1
    return f"{line}.{offset - line_start}"


def _make_app(source, references, offset):
    tab = EditorTab(
        dalvik_class="Lexample/Test;",
        title="Test",
        source=source,
        loading=False,
        member_references=references,
    )
    started = []
    app = SimpleNamespace(
        _active_tab=lambda: tab,
        source_text=SimpleNamespace(index=lambda _mark: _text_index(source, offset)),
        search_type_var=_Value(),
        search_value_var=_Value(),
        search_class_var=_Value(),
        fuzzy_class_var=_Value(True),
        status_var=_Value(),
        _on_search_type_changed=lambda: None,
        _start_search=lambda **kwargs: started.append(kwargs),
    )
    app._member_at_index = lambda index: AscGuiApp._member_at_index(app, index)
    return app, started


class SourceEditTests(unittest.TestCase):
    def test_rendered_member_ranges_follow_inserted_line_comments(self):
        source = "void first() {}\nvoid second() {}\n"
        first = source.index("first")
        second = source.index("second")
        tab = EditorTab(
            dalvik_class="Lexample/Test;", title="Test", source=source, loading=False,
            comments={1: "note"},
            member_references=[
                (first, first + 5, "method", "Lexample/Test;", "first", "()V", True),
                (second, second + 6, "method", "Lexample/Test;", "second", "()V", True),
            ],
        )

        rendered, _comment_spans = AscGuiApp._render_tab_source(SimpleNamespace(), tab)

        self.assertEqual(
            rendered[tab.rendered_member_references[0][0]:tab.rendered_member_references[0][1]],
            "first",
        )
        self.assertEqual(
            rendered[tab.rendered_member_references[1][0]:tab.rendered_member_references[1][1]],
            "second",
        )

    def test_ctrl_click_passes_exact_target_to_navigation(self):
        target = (4, 8, "method", "Lexample/Target;", "call", "(I)V", False)
        opened = []
        completed = []
        app = SimpleNamespace(
            source_text=_NavigationText("1.5"),
            _member_at_index=lambda _index: target,
            store=SimpleNamespace(class_to_dex={"Lexample/Target;": "classes.dex"}),
            status_var=_Value(),
            _pending_member_navigation=None,
            open_class=lambda class_name: opened.append(class_name),
            _complete_pending_member_navigation=lambda class_name: completed.append(class_name),
        )

        result = AscGuiApp._open_member_from_click(app, SimpleNamespace(x=10, y=20))

        self.assertEqual(result, "break")
        self.assertEqual(
            app._pending_member_navigation,
            ("Lexample/Target;", "method", "call", "(I)V"),
        )
        self.assertEqual(opened, ["Lexample/Target;"] )
        self.assertEqual(completed, ["Lexample/Target;"] )

    def test_pending_navigation_moves_to_exact_declaration(self):
        wrong = (12, 15, "method", "Lexample/Target;", "run", "()V", True)
        target = (40, 43, "method", "Lexample/Target;", "run", "(I)V", True)
        tab = EditorTab(
            dalvik_class="Lexample/Target;", title="Target", source="x" * 80,
            loading=False, rendered_member_references=[wrong, target],
        )
        text = _NavigationText()
        app = SimpleNamespace(
            _pending_member_navigation=("Lexample/Target;", "method", "run", "(I)V"),
            editor_tabs=[tab],
            _find_tab_index=lambda _class_name: 0,
            source_text=text,
            _highlight_active_line=lambda: None,
            _highlight_related_identifier=lambda _index: None,
            status_var=_Value(),
        )

        AscGuiApp._complete_pending_member_navigation(app, "Lexample/Target;")

        self.assertIsNone(app._pending_member_navigation)
        self.assertEqual(text.insert, "1.0+40c")
        self.assertEqual(text.seen, ["1.0+40c"] )
        self.assertEqual(tab.insert_index, "1.0+40c")

    def test_ctrl_underline_marks_only_linkable_member_ranges(self):
        references = [
            (1, 4, "method", "Llocal/Target;", "run", "()V", False),
            (8, 13, "field", "Ljava/lang/System;", "value", "I", False),
        ]
        tab = EditorTab(
            dalvik_class="Llocal/Source;", title="Source", source="x" * 20,
            loading=False, rendered_member_references=references,
        )
        applied = []
        text = _NavigationText()
        app = SimpleNamespace(
            _ctrl_member_links_visible=False,
            source_text=text,
            _active_tab=lambda: tab,
            store=SimpleNamespace(class_to_dex={"Llocal/Target;": "classes.dex"}),
            _tag_ranges=lambda name, spans: applied.append((name, spans)),
        )

        AscGuiApp._show_member_links(app)

        self.assertTrue(app._ctrl_member_links_visible)
        self.assertEqual(applied, [("member_link", [(1, 4)])])
        self.assertIn(("raise", "member_link"), text.tags)

    def test_member_hit_requires_cursor_on_member_name(self):
        reference = (10, 14, "method", "LTarget;", "call", "()V", False)
        self.assertEqual(member_reference_at_offset([reference], 10), reference)
        self.assertEqual(member_reference_at_offset([reference], 13), reference)
        self.assertIsNone(member_reference_at_offset([reference], 9))
        self.assertIsNone(member_reference_at_offset([reference], 14))

    def test_navigation_selects_exact_method_overload(self):
        declarations = [
            (10, 13, "method", "LTarget;", "run", "()V", True),
            (30, 33, "method", "LTarget;", "run", "(I)V", True),
        ]
        self.assertEqual(
            find_member_declaration(declarations, "method", "run", "(I)V"),
            declarations[1],
        )

    def test_navigation_selects_exact_field_type(self):
        declarations = [
            (10, 15, "field", "LTarget;", "value", "I", True),
        ]
        self.assertEqual(
            find_member_declaration(declarations, "field", "value", "I"),
            declarations[0],
        )
        self.assertIsNone(find_member_declaration(
            declarations, "field", "value", "Ljava/lang/String;"
        ))

    def test_ctrl_underline_only_marks_members_in_apk(self):
        references = [
            (1, 4, "method", "Llocal/Target;", "run", "()V", False),
            (8, 13, "field", "Ljava/lang/System;", "value", "I", False),
        ]
        self.assertEqual(
            linkable_member_spans(references, {"Llocal/Target;": "classes.dex"}),
            [(1, 4)],
        )

    def test_real_this_field_method_chain_maps_both_members(self):
        from dex_fixture import make_field_invoke_chain_dex
        from droidasc.asc_client.asc_handler import AscHandler

        source, references = AscHandler().getclass_with_metadata(
            make_field_invoke_chain_dex(), "Lexample/Test;"
        )
        field = next(item for item in references if item[2:5] == (
            "field", "Lexample/Test;", "a"
        ))
        method = next(item for item in references if item[2:5] == (
            "method", "Lexample/Target;", "callToMethod"
        ))
        self.assertEqual(source[field[0]:field[1]], "a")
        self.assertEqual(source[method[0]:method[1]], "callToMethod")

    def test_rename_keeps_later_member_reference_offsets_aligned(self):
        source = "int v1 = 0; target.call();"
        call_start = source.index("call")
        references = [(call_start, call_start + 4, "method", "LTarget;", "call", "()V", False)]
        remapped = remap_ranges_after_replacements(
            references, [(source.index("v1"), source.index("v1") + 2)], len("value")
        )
        new_source = source.replace("v1", "value")
        self.assertEqual(new_source[remapped[0][0]:remapped[0][1]], "call")

    def test_unicode_decoding_keeps_method_reference_offsets_aligned(self):
        source = '"\\u4f60"; void run() {}'
        start = source.index("run")
        decoded, references = decode_java_unicode_escapes_with_ranges(
            source, [(start, start + 3, "method", "Lexample/Test;", "run", "()V", True)]
        )
        ref_start, ref_end, *_metadata = references[0]
        self.assertEqual(decoded[ref_start:ref_end], "run")

    def test_real_dex_invocation_metadata_has_target_class(self):
        from dex_fixture import make_invoke_dex
        from droidasc.asc_client.asc_handler import AscHandler

        source, references = AscHandler().getclass_with_metadata(
            make_invoke_dex(), "Lexample/Test;"
        )
        invocation = next(item for item in references if item[4] == "callToMethod")
        self.assertEqual(source[invocation[0]:invocation[1]], "callToMethod")
        self.assertEqual(
            invocation[2:], ("method", "Lexample/Target;", "callToMethod", "()V", False)
        )

    def test_real_dex_static_field_metadata_has_declaring_class(self):
        from dex_fixture import make_static_field_dex
        from droidasc.asc_client.asc_handler import AscHandler

        source, references = AscHandler().getclass_with_metadata(
            make_static_field_dex(), "Lexample/Statics;"
        )
        matches = [item for item in references if item[4] == "SECOND"]
        self.assertEqual(len(matches), 2)
        self.assertTrue(all(source[item[0]:item[1]] == "SECOND" for item in matches))
        self.assertTrue(all(item[2:6] == (
            "field", "Lexample/Statics;", "SECOND", "I"
        ) for item in matches))

    def test_real_dex_instance_field_metadata_has_declaring_class(self):
        from dex_fixture import make_instance_field_dex
        from droidasc.asc_client.asc_handler import AscHandler

        source, references = AscHandler().getclass_with_metadata(
            make_instance_field_dex(), "Lexample/Test;"
        )
        matches = [item for item in references if item[2] == "field" and item[4] == "a"]
        self.assertEqual(len(matches), 2)
        self.assertTrue(all(source[item[0]:item[1]] == "a" for item in matches))
        self.assertTrue(all(item[3] == "Lexample/Test;" for item in matches))

    def test_source_metadata_uses_declaration_and_invoke_classes(self):
        declared = SimpleNamespace(
            cls_name="Lexample/Test;", name="run",
            triple=("example/Test", "run", "()V"),
        )
        invoked = SimpleNamespace(
            cls="example.Target",
            name="callToMethod",
            triple=("example/Target", "callToMethod", "()V"),
        )
        source, references = _source_with_member_references([
            ("METHOD", [
                ("NAME_METHOD_PROTOTYPE", "run", declared),
                ("TEXT", " { this.a."),
                ("NAME_METHOD_INVOKE", "callToMethod", "ignored", None, None, None, invoked),
                ("TEXT", "(); }"),
            ]),
        ])

        self.assertEqual(source, "run { this.a.callToMethod(); }")
        self.assertEqual(references, [
            (0, 3, "method", "Lexample/Test;", "run", "()V", True),
            (13, 25, "method", "Lexample/Target;", "callToMethod", "()V", False),
        ])

    def test_x_on_method_declaration_searches_current_class(self):
        source = "public void run()\n{\n    return;\n}\n"
        start = source.index("run")
        app, started = _make_app(
            source, [(start, start + 3, "method", "Lexample/Test;", "run", "()V", True)], start + 1
        )

        result = AscGuiApp._find_current_member_references(app)

        self.assertEqual(result, "break")
        self.assertEqual(app.search_value_var.get(), "run")
        self.assertEqual(app.search_class_var.get(), "Lexample/Test;")
        self.assertEqual(started, [{"exact_member": True}])

    def test_x_on_invocation_uses_invoked_method_class(self):
        source = "public void run() { this.a.callToMethod(); }"
        start = source.index("callToMethod")
        app, started = _make_app(
            source,
            [(start, start + len("callToMethod"), "method", "Lexample/Target;", "callToMethod", "()V", False)],
            start + 2,
        )

        AscGuiApp._find_current_member_references(app)

        self.assertEqual(app.search_value_var.get(), "callToMethod")
        self.assertEqual(app.search_class_var.get(), "Lexample/Target;")
        self.assertEqual(started, [{"exact_member": True}])

    def test_x_on_field_access_uses_declaring_field_class(self):
        source = "public void run() { this.a = target.value; }"
        start = source.index("value")
        app, started = _make_app(
            source,
            [(start, start + len("value"), "field", "Lexample/Target;", "value", "I", False)],
            start + 2,
        )

        AscGuiApp._find_current_member_references(app)

        self.assertEqual(app.search_type_var.get(), "field refs")
        self.assertEqual(app.search_value_var.get(), "value")
        self.assertEqual(app.search_class_var.get(), "Lexample/Target;")
        self.assertEqual(started, [{"exact_member": True}])

    def test_x_inside_method_but_not_on_method_name_does_not_search(self):
        source = "public void run()\n{\n    return;\n}\n"
        start = source.index("run")
        app, started = _make_app(
            source, [(start, start + 3, "method", "Lexample/Test;", "run", "()V", True)], source.index("return")
        )

        AscGuiApp._find_current_member_references(app)

        self.assertEqual(started, [])
        self.assertEqual(
            app.status_var.get(),
            "Place the cursor on a method or field name to find its references",
        )

    def test_x_uses_exact_method_name_query(self):
        find_type, query = build_find_query(
            "method refs", "foo", "Lexample/Test;", exact_member=True
        )
        self.assertEqual(find_type, "method")
        self.assertEqual(query, {
            "method": {"class": ["Lexample/Test;", True], "method": ["foo", True]}
        })

    def test_exact_method_locator_does_not_use_substring_matching(self):
        from dex_fixture import make_dex

        dex = DEX.parse(memoryview(make_dex()), "fixture.dex")
        locator = FindRefManager(dex)._get_method_locator(True)
        self.assertEqual(locator.locate({
            "class": ["Lexample/Test;", True],
            "method": ["fir", True],
        }), set())
        self.assertEqual(locator.locate({
            "class": ["Lexample/Test;", True],
            "method": ["first", True],
        }), {0})

    def test_exact_field_locator_does_not_use_substring_matching(self):
        from dex_fixture import make_static_field_dex

        dex = DEX.parse(memoryview(make_static_field_dex()), "fixture.dex")
        locator = FindRefManager(dex)._get_field_locator(True)
        self.assertEqual(locator.locate({
            "class": ["Lexample/Statics;", True],
            "field": ["SEC", True],
        }), set())
        self.assertEqual(locator.locate({
            "class": ["Lexample/Statics;", True],
            "field": ["SECOND", True],
        }), {1})


if __name__ == "__main__":
    unittest.main()
