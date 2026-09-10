import struct


_U32 = struct.Struct("<I")
_U32_FROM = _U32.unpack_from
_DEX_HEADER_MIN_SIZE = 0x70
_DEX041_MAGIC = b"dex\n041\x00"


def is_dex041_container(data : bytes):
    return len(data) >= _DEX_HEADER_MIN_SIZE and data[:8] == _DEX041_MAGIC


def dex041_logical_offsets(data : bytes):
    if not is_dex041_container(data):
        return [0]
    offsets = []
    off = 0
    data_len = len(data)
    while off + _DEX_HEADER_MIN_SIZE <= data_len and data[off:off + 8] == _DEX041_MAGIC:
        file_size = _U32_FROM(data, off + 0x20)[0]
        if file_size < _DEX_HEADER_MIN_SIZE or off + file_size > data_len:
            break
        offsets.append(off)
        off += file_size
    return offsets or [0]


def _patch_u32(buf : bytearray, off : int, delta : int):
    val = _U32_FROM(buf, off)[0]
    if val != 0 and val != 0xFFFFFFFF and val >= delta:
        buf[off:off + 4] = (val - delta).to_bytes(4, "little")


def _read_uleb128(buf, off : int):
    result = 0
    shift = 0
    pos = off
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, pos - off
        shift += 7


def _write_uleb128(value : int):
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return out


def _patch_uleb128_in_place(buf : bytearray, off : int, delta : int):
    value, size = _read_uleb128(buf, off)
    if value == 0 or value < delta:
        return size
    new_data = _write_uleb128(value - delta)
    if len(new_data) != size:
        # DEX041 keeps physical offsets. In practice subtracting the container
        # base can shrink a uleb128. Avoid shifting the whole DEX here; leave it
        # untouched rather than corrupting following fields.
        return size
    buf[off:off + size] = new_data
    return size


def normalize_dex041_logical(data : bytes, header_off : int):
    if header_off == 0:
        return data
    header_size = _U32_FROM(data, header_off + 0x24)[0]
    if header_size < _DEX_HEADER_MIN_SIZE or header_off + header_size > len(data):
        header_size = _DEX_HEADER_MIN_SIZE
    out = bytearray(data)
    out[:header_size] = data[header_off:header_off + header_size]
    return bytes(out)


def _patch_class_data_code_offsets(buf : bytearray, class_defs_off : int, class_defs_size : int, delta : int):
    for class_idx in range(class_defs_size):
        class_def_off = class_defs_off + class_idx * 32
        if class_def_off + 32 > len(buf):
            break
        class_data_off = _U32_FROM(buf, class_def_off + 24)[0]
        if class_data_off == 0 or class_data_off >= len(buf):
            continue
        p = class_data_off
        static_fields_size, n = _read_uleb128(buf, p); p += n
        instance_fields_size, n = _read_uleb128(buf, p); p += n
        direct_methods_size, n = _read_uleb128(buf, p); p += n
        virtual_methods_size, n = _read_uleb128(buf, p); p += n
        for _ in range(static_fields_size + instance_fields_size):
            _, n = _read_uleb128(buf, p); p += n
            _, n = _read_uleb128(buf, p); p += n
        for _ in range(direct_methods_size + virtual_methods_size):
            _, n = _read_uleb128(buf, p); p += n
            _, n = _read_uleb128(buf, p); p += n
            p += _patch_uleb128_in_place(buf, p, delta)


def _patch_code_item_debug_offsets(buf : bytearray, delta : int):
    map_off = _U32_FROM(buf, 0x34)[0]
    if not (0 < map_off + 4 <= len(buf)):
        return
    map_size = _U32_FROM(buf, map_off)[0]
    p = map_off + 4
    code_off = 0
    code_size = 0
    for _ in range(map_size):
        if p + 12 > len(buf):
            return
        typ = int.from_bytes(buf[p:p + 2], "little")
        size = _U32_FROM(buf, p + 4)[0]
        off = _U32_FROM(buf, p + 8)[0]
        if typ == 0x2001:
            code_size = size
            code_off = off
            break
        p += 12
    p = code_off
    for _ in range(code_size):
        if p + 16 > len(buf):
            break
        _patch_u32(buf, p + 8, delta)
        insns_size = _U32_FROM(buf, p + 12)[0]
        tries_size = int.from_bytes(buf[p + 6:p + 8], "little")
        p = p + 16 + insns_size * 2
        if tries_size:
            if p & 3:
                p += 2
            p += tries_size * 8
            # encoded_catch_handler_list is variable length. Use the next code
            # item alignment from map only as best effort is not available here.
            # Existing code paths only need debug_off fixed before bytecode read.
        while p & 3:
            p += 1


def iter_logical_dex_buffers(name : str, data : bytes):
    offsets = dex041_logical_offsets(data)
    if len(offsets) <= 1:
        yield name, data
        return
    for idx, header_off in enumerate(offsets):
        logical_name = f"{name}!classes{idx + 1}.dex"
        yield logical_name, normalize_dex041_logical(data, header_off)
