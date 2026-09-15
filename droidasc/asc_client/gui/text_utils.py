def decode_java_unicode_escapes(text : str):
    if "\\u" not in text:
        return text

    out = []
    pending_high = None
    pending_high_raw = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch != "\\" or i + 1 >= n or text[i + 1] != "u":
            if pending_high is not None:
                out.append(pending_high_raw)
                pending_high = None
                pending_high_raw = None
            out.append(ch)
            i += 1
            continue

        escape_start = i
        j = i + 1
        while j < n and text[j] == "u":
            j += 1
        if j + 4 > n:
            if pending_high is not None:
                out.append(pending_high_raw)
                pending_high = None
                pending_high_raw = None
            out.append(ch)
            i += 1
            continue

        hex_part = text[j:j + 4]
        try:
            code_unit = int(hex_part, 16)
        except ValueError:
            if pending_high is not None:
                out.append(pending_high_raw)
                pending_high = None
                pending_high_raw = None
            out.append(ch)
            i += 1
            continue

        i = j + 4
        raw_escape = text[escape_start:i]
        if code_unit == 0xFFFD:
            if pending_high is not None:
                out.append(pending_high_raw)
                pending_high = None
                pending_high_raw = None
            out.append(raw_escape)
            continue
        if 0xD800 <= code_unit <= 0xDBFF:
            if pending_high is not None:
                out.append(pending_high_raw)
            pending_high = code_unit
            pending_high_raw = raw_escape
            continue

        if pending_high is not None:
            if 0xDC00 <= code_unit <= 0xDFFF:
                code_point = 0x10000 + ((pending_high - 0xD800) << 10) + (code_unit - 0xDC00)
                out.append(chr(code_point))
                pending_high = None
                pending_high_raw = None
                continue
            out.append(pending_high_raw)
            pending_high = None
            pending_high_raw = None

        if 0xDC00 <= code_unit <= 0xDFFF:
            out.append(raw_escape)
            continue

        out.append(chr(code_unit))

    if pending_high is not None:
        out.append(pending_high_raw)
    return "".join(out)
