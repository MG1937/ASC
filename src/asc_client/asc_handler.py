import copy
from collections import defaultdict


class AscHandler:
    def __init__(self, debug : bool = False):
        self.debug = debug

    def getclass(self, dex_buf : bytes, dalvik_class : str) -> str:
        from src.asc_core.core.dex.dex_manager import DexManager
        from src.asc_core.utils.decompiler import decompile_dex_bytes

        manager = DexManager(memoryview(dex_buf), debug=self.debug)
        new_dex_bytes = manager.extract_and_rebuild(dalvik_class)
        return decompile_dex_bytes(new_dex_bytes, dalvik_class)

    def _format_method(self, dex, midx : int) -> str:
        method = dex.methods[midx]
        return f"{method.cls.fullname}->{method.name}"

    def _format_matched_name(self, dex, find_type : str, idx : int) -> str:
        if find_type == "string":
            return str(dex.strings[idx])
        if find_type == "type":
            return dex.types[idx].descriptor
        if find_type == "method":
            method = dex.methods[idx]
            return f"{method.cls.fullname}->{method.name}"
        field = dex.fields[idx]
        return f"{field.cls.fullname}->{field.name}"

    def findrefs(self, dex_name : str, dex_buf : bytes, find_type : str, find : dict, aggregate : bool = True) -> list:
        from src.asc_core.findrefs.findrefs_manager import FindRefManager
        from src.asc_core.utils.tinydex import DEX

        dex = DEX.parse(memoryview(dex_buf), dex_name)
        ref_manager = FindRefManager(dex)
        query = copy.deepcopy(find)
        matched_idxs = ref_manager.find_ref(query, True)
        mids = query[find_type]
        if not aggregate:
            ret = []
            for i in range(len(mids)):
                midx = mids[i]
                if midx is None:
                    continue
                idx = matched_idxs[i]
                if isinstance(midx, list):
                    midxs = midx
                else:
                    midxs = [midx]
                matched = self._format_matched_name(dex, find_type, idx)
                for mid in midxs:
                    ret.append(
                        f"{dex_name} | {self._format_method(dex, mid)} | matched=({matched})"
                    )
            return ret

        grouped = defaultdict(set)
        for i in range(len(mids)):
            midx = mids[i]
            if midx is None:
                continue
            idx = matched_idxs[i]
            if isinstance(midx, list):
                midxs = midx
            else:
                midxs = [midx]
            for mid in midxs:
                grouped[mid].add(idx)

        ret = []
        for mid in sorted(grouped):
            matched = "; ".join(
                self._format_matched_name(dex, find_type, idx)
                for idx in sorted(grouped[mid])
            )
            ret.append(
                f"{dex_name} | {self._format_method(dex, mid)} | matched=({matched})"
            )
        return ret
