_IDENT_START_EXTRA = "_$"
_IDENT_EXTRA = "_$"
_BLOCK_PREFIXES = (
    "if ", "if(", "for ", "for(", "while ", "while(", "switch ", "switch(",
    "catch ", "catch(", "else", "try", "do",
)


def _is_ident_start(ch : str):
    return ch.isalpha() or ch in _IDENT_START_EXTRA


def _is_ident(ch : str):
    return ch.isalnum() or ch in _IDENT_EXTRA


def index_to_offset(text : str, index : str):
    line_s, col_s = str(index).split(".", 1)
    line_no = int(line_s)
    col = int(col_s)
    if line_no <= 1:
        return min(col, len(text))
    off = 0
    cur_line = 1
    while cur_line < line_no and off < len(text):
        nl = text.find("\n", off)
        if nl < 0:
            return len(text)
        off = nl + 1
        cur_line += 1
    return min(off + col, len(text))


def token_at_offset(text : str, offset : int):
    if not text:
        return None
    offset = max(0, min(offset, len(text) - 1))
    if not _is_ident(text[offset]):
        if offset > 0 and _is_ident(text[offset - 1]):
            offset -= 1
        else:
            return None
    start = offset
    while start > 0 and _is_ident(text[start - 1]):
        start -= 1
    end = offset + 1
    while end < len(text) and _is_ident(text[end]):
        end += 1
    token = text[start:end]
    if not token or not _is_ident_start(token[0]):
        return None
    return start, end, token


def is_identifier(text : str):
    if not text or not _is_ident_start(text[0]):
        return False
    return all(_is_ident(ch) for ch in text[1:])


def find_method_range(text : str, offset : int):
    offset = max(0, min(offset, len(text)))
    signature_range = _method_range_from_signature_line(text, offset)
    if signature_range is not None:
        return signature_range

    brace = text.rfind("{", 0, offset + 1)
    while brace >= 0:
        line_start, prefix = _prefix_before_brace(text, brace)
        if _looks_like_method_prefix(prefix):
            end = _matching_brace(text, brace)
            if end is not None and brace <= offset <= end:
                return line_start, end + 1
        brace = text.rfind("{", 0, brace)
    return None


def _prefix_before_brace(text : str, brace : int):
    line_start = text.rfind("\n", 0, brace) + 1
    prefix = text[line_start:brace].strip()
    if prefix:
        return line_start, prefix

    prev_end = line_start - 1
    if prev_end < 0 or text[prev_end:prev_end + 1] != "\n":
        return line_start, prefix
    prev_start = text.rfind("\n", 0, prev_end) + 1
    return prev_start, text[prev_start:prev_end].strip()


def _method_range_from_signature_line(text : str, offset : int):
    line_start = text.rfind("\n", 0, offset) + 1
    line_end_pos = text.find("\n", offset)
    if line_end_pos < 0:
        line_end_pos = len(text)
    current_line = text[line_start:line_end_pos]
    if "(" not in current_line or ")" not in current_line:
        return None

    search_end = min(len(text), line_end_pos + 1)
    open_brace = text.find("{", line_start, search_end)
    if open_brace < 0:
        next_line_end = text.find("\n", line_end_pos + 1)
        if next_line_end < 0:
            next_line_end = len(text)
        between = text[line_end_pos + 1:next_line_end].strip()
        if between != "{":
            return None
        open_brace = text.find("{", line_end_pos + 1, next_line_end + 1)

    prefix = text[line_start:open_brace].strip()
    if not _looks_like_method_prefix(prefix):
        return None
    end = _matching_brace(text, open_brace)
    if end is None:
        return None
    return line_start, end + 1


def _looks_like_method_prefix(prefix : str):
    if not prefix or prefix.startswith(_BLOCK_PREFIXES):
        return False
    if "(" not in prefix or ")" not in prefix:
        return False
    if prefix.endswith(("=", ".", ",")):
        return False
    return True


def _matching_brace(text : str, open_pos : int):
    depth = 0
    state = "code"
    i = open_pos
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if ch == '"':
                state = "string"
                i += 1
                continue
            if ch == "'":
                state = "char"
                i += 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        elif state == "line_comment":
            if ch == "\n":
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
                continue
        elif state == "string":
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                state = "code"
        elif state == "char":
            if ch == "\\":
                i += 2
                continue
            if ch == "'":
                state = "code"
        i += 1
    return None


def rename_identifier_in_range(text : str, start : int, end : int, old : str, new : str):
    out = []
    spans = []
    last = start
    state = "code"
    i = start
    while i < end:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < end else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if ch == '"':
                state = "string"
                i += 1
                continue
            if ch == "'":
                state = "char"
                i += 1
                continue
            if _is_ident_start(ch):
                tok_start = i
                i += 1
                while i < end and _is_ident(text[i]):
                    i += 1
                if text[tok_start:i] == old:
                    out.append(text[last:tok_start])
                    out.append(new)
                    spans.append((tok_start, i))
                    last = i
                continue
        elif state == "line_comment":
            if ch == "\n":
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
                continue
        elif state == "string":
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                state = "code"
        elif state == "char":
            if ch == "\\":
                i += 2
                continue
            if ch == "'":
                state = "code"
        i += 1
    if not spans:
        return text, 0
    out.append(text[last:end])
    return text[:start] + "".join(out) + text[end:], len(spans)


def identifier_occurrences_in_range(text : str, start : int, end : int, name : str):
    spans = []
    state = "code"
    i = start
    while i < end:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < end else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if ch == '"':
                state = "string"
                i += 1
                continue
            if ch == "'":
                state = "char"
                i += 1
                continue
            if _is_ident_start(ch):
                tok_start = i
                i += 1
                while i < end and _is_ident(text[i]):
                    i += 1
                if text[tok_start:i] == name:
                    spans.append((tok_start, i))
                continue
        elif state == "line_comment":
            if ch == "\n":
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
                continue
        elif state == "string":
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                state = "code"
        elif state == "char":
            if ch == "\\":
                i += 2
                continue
            if ch == "'":
                state = "code"
        i += 1
    return spans
