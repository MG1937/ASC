# Auth: MG1937
from findrefs.locator.insn_locator import InsnLocator
from findrefs.locator.field_locator import FieldLocator
from findrefs.locator.method_locator import MethodLocator
from findrefs.locator.string_locator import StringLocator
from findrefs.locator.type_locator import TypeLocator
from findrefs.scan.code_item_scan import CodeItemScanner


class FindRefManager:
    def __init__(self, dex):
        self.dex = dex
        self.str_locator = None
        self.type_locator = None
        self.method_locator = None
        self.field_locator = None
        self.insn_locator = None
        self.code_scanner = None

    def _get_str_locator(self, build = False):
        locator = self.str_locator
        if locator is None:
            locator = StringLocator(self.dex)
            self.str_locator = locator
        if build and not locator.parsed:
            locator._build_map()
        return locator

    def _get_type_locator(self, build = False):
        locator = self.type_locator
        if locator is None:
            locator = TypeLocator(self.dex)
            locator.set_str_locator(self._get_str_locator(True))
            self.type_locator = locator
        if build and not locator.parsed:
            locator._build_map()
        return locator

    def _get_method_locator(self, build = False):
        locator = self.method_locator
        if locator is None:
            locator = MethodLocator(self.dex)
            locator.set_str_locator(self._get_str_locator(True))
            locator.set_type_locator(self._get_type_locator(True))
            self.method_locator = locator
        if build and not locator.parsed:
            locator._build_map()
        return locator

    def _get_field_locator(self, build = False):
        locator = self.field_locator
        if locator is None:
            locator = FieldLocator(self.dex)
            locator.set_str_locator(self._get_str_locator(True))
            locator.set_type_locator(self._get_type_locator(True))
            self.field_locator = locator
        if build and not locator.parsed:
            locator._build_map()
        return locator

    def _get_code_scanner(self):
        insn_locator = self.insn_locator
        if insn_locator is None:
            insn_locator = InsnLocator(self.dex)
            self.insn_locator = insn_locator
        if not insn_locator.parsed:
            insn_locator.parse()

        scanner = self.code_scanner
        if scanner is None:
            scanner = CodeItemScanner(insn_locator)
            self.code_scanner = scanner
        return scanner

    # find struct: {"string" : "foo", "type" : "bar", "method" : {...}, "field" : {...}}
    # locate result will overwrite input find in-place, then scanner writes ref mids back into each key
    def find_ref(self, find : dict, mark = False):
        has_idx = False
        if "string" in find:
            find["string"] = self._get_str_locator(True).locate(find["string"])
            if find["string"]:
                has_idx = True
        if "type" in find:
            find["type"] = self._get_type_locator(True).locate(find["type"])
            if find["type"]:
                has_idx = True
        if "method" in find:
            find["method"] = self._get_method_locator(True).locate(find["method"])
            if find["method"]:
                has_idx = True
        if "field" in find:
            find["field"] = self._get_field_locator(True).locate(find["field"])
            if find["field"]:
                has_idx = True

        if not find:
            return
        if not has_idx:
            for type_ in find:
                find[type_] = []
            return []

        self._get_code_scanner().scan(find, mark)
        return self._get_code_scanner().mark_idx
