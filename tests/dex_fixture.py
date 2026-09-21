"""Build a small DEX with two static methods sharing one code_item."""
import hashlib
import struct
import zlib


def uleb(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return result


def make_dex():
    strings = [b'Lexample/Test;', b'Ljava/lang/Object;', b'V', b'first', b'second', b'token']
    buf = bytearray(112)
    sections = [(0, 1, 0)]

    def section(kind, size, data, align=4):
        buf.extend(b'\0' * (-len(buf) % align))
        off = len(buf)
        sections.append((kind, size, off))
        buf.extend(data)
        return off

    string_ids = section(1, len(strings), bytes(4 * len(strings)))
    type_ids = section(2, 3, struct.pack('<III', 0, 1, 2))
    proto_ids = section(3, 1, struct.pack('<III', 2, 2, 0))
    method_ids = section(5, 2, struct.pack('<HHIHHI', 0, 0, 3, 0, 0, 4))
    class_defs = section(6, 1, bytes(32))
    data_off = len(buf)
    string_data = b''.join(uleb(len(s)) + s + b'\0' for s in strings)
    off = section(0x2002, len(strings), string_data, align=1)
    for i, value in enumerate(strings):
        struct.pack_into('<I', buf, string_ids + 4 * i, off)
        off += len(uleb(len(value))) + len(value) + 1
    # const-string v0, string@5; return-void
    code = section(0x2001, 1, struct.pack('<HHHHII', 1, 0, 0, 0, 0, 3) + b'\x1a\0\x05\0\x0e\0')
    class_data = section(0x2000, 1, b'\0\0\x02\0' + b'\0\x09' + uleb(code) + b'\x01\x09' + uleb(code), align=1)
    struct.pack_into('<IIIIIIII', buf, class_defs, 0, 1, 1, 0, 0xffffffff, 0, class_data, 0)
    buf.extend(b'\0' * (-len(buf) % 4))
    map_off = len(buf)
    sections.append((0x1000, 1, map_off))
    buf.extend(struct.pack('<I', len(sections)))
    for kind, count, offset in sections:
        buf.extend(struct.pack('<HHII', kind, 0, count, offset))
    buf[:8] = b'dex\n035\0'
    struct.pack_into('<IIIIII', buf, 32, len(buf), 112, 0x12345678, 0, 0, map_off)
    struct.pack_into('<IIIIIIIIIIIIII', buf, 56,
                     len(strings), string_ids, 3, type_ids, 1, proto_ids,
                     0, 0, 2, method_ids, 1, class_defs, len(buf) - data_off, data_off)
    buf[12:32] = hashlib.sha1(buf[32:]).digest()
    struct.pack_into('<I', buf, 8, zlib.adler32(buf[12:]) & 0xffffffff)
    return bytes(buf)


def make_invoke_dex():
    """Build a class whose run method invokes example.Target.callToMethod."""
    strings = [
        b'Lexample/Test;', b'Ljava/lang/Object;', b'V', b'run',
        b'Lexample/Target;', b'callToMethod',
    ]
    buf = bytearray(112)
    sections = [(0, 1, 0)]

    def section(kind, size, data, align=4):
        buf.extend(b'\0' * (-len(buf) % align))
        off = len(buf)
        sections.append((kind, size, off))
        buf.extend(data)
        return off

    string_ids = section(1, len(strings), bytes(4 * len(strings)))
    type_ids = section(2, 4, struct.pack('<IIII', 0, 1, 2, 4))
    proto_ids = section(3, 1, struct.pack('<III', 2, 2, 0))
    method_ids = section(5, 2, struct.pack('<HHIHHI', 0, 0, 3, 3, 0, 5))
    class_defs = section(6, 1, bytes(32))
    data_off = len(buf)
    string_data = b''.join(uleb(len(s)) + s + b'\0' for s in strings)
    off = section(0x2002, len(strings), string_data, align=1)
    for i, value in enumerate(strings):
        struct.pack_into('<I', buf, string_ids + 4 * i, off)
        off += len(uleb(len(value))) + len(value) + 1

    # invoke-static {}, method@1; return-void
    code = section(
        0x2001, 1,
        struct.pack('<HHHHII', 0, 0, 0, 0, 0, 4) + b'\x71\x00\x01\x00\x00\x00\x0e\x00',
    )
    class_data = section(0x2000, 1, b'\0\0\x01\0' + b'\0\x09' + uleb(code), align=1)
    struct.pack_into('<IIIIIIII', buf, class_defs, 0, 1, 1, 0, 0xffffffff, 0, class_data, 0)
    buf.extend(b'\0' * (-len(buf) % 4))
    map_off = len(buf)
    sections.append((0x1000, 1, map_off))
    buf.extend(struct.pack('<I', len(sections)))
    for kind, count, offset in sections:
        buf.extend(struct.pack('<HHII', kind, 0, count, offset))
    buf[:8] = b'dex\n035\0'
    struct.pack_into('<IIIIII', buf, 32, len(buf), 112, 0x12345678, 0, 0, map_off)
    struct.pack_into('<IIIIIIIIIIIIII', buf, 56,
                     len(strings), string_ids, 4, type_ids, 1, proto_ids,
                     0, 0, 2, method_ids, 1, class_defs, len(buf) - data_off, data_off)
    buf[12:32] = hashlib.sha1(buf[32:]).digest()
    struct.pack_into('<I', buf, 8, zlib.adler32(buf[12:]) & 0xffffffff)
    return bytes(buf)


def make_instance_field_dex():
    """Build a class whose getA method reads this.a with iget-object."""
    strings = [
        b'Lexample/Test;', b'Ljava/lang/Object;', b'Lexample/Target;',
        b'L', b'getA', b'a',
    ]
    buf = bytearray(112)
    sections = [(0, 1, 0)]

    def section(kind, size, data, align=4):
        buf.extend(b'\0' * (-len(buf) % align))
        off = len(buf)
        sections.append((kind, size, off))
        buf.extend(data)
        return off

    string_ids = section(1, len(strings), bytes(4 * len(strings)))
    type_ids = section(2, 3, struct.pack('<III', 0, 1, 2))
    proto_ids = section(3, 1, struct.pack('<III', 3, 2, 0))
    field_ids = section(4, 1, struct.pack('<HHI', 0, 2, 5))
    method_ids = section(5, 1, struct.pack('<HHI', 0, 0, 4))
    class_defs = section(6, 1, bytes(32))
    data_off = len(buf)
    string_data = b''.join(uleb(len(s)) + s + b'\0' for s in strings)
    off = section(0x2002, len(strings), string_data, align=1)
    for i, value in enumerate(strings):
        struct.pack_into('<I', buf, string_ids + 4 * i, off)
        off += len(uleb(len(value))) + len(value) + 1

    # iget-object v0, p0, field@0; return-object v0
    code = section(
        0x2001, 1,
        struct.pack('<HHHHII', 1, 1, 0, 0, 0, 3) + b'\x54\x00\x00\x00\x11\x00',
    )
    class_data = section(
        0x2000, 1, b'\x00\x01\x00\x01' + b'\x00\x01' + b'\x00\x01' + uleb(code),
        align=1,
    )
    struct.pack_into('<IIIIIIII', buf, class_defs, 0, 1, 1, 0, 0xffffffff, 0, class_data, 0)
    buf.extend(b'\0' * (-len(buf) % 4))
    map_off = len(buf)
    sections.append((0x1000, 1, map_off))
    buf.extend(struct.pack('<I', len(sections)))
    for kind, count, offset in sections:
        buf.extend(struct.pack('<HHII', kind, 0, count, offset))
    buf[:8] = b'dex\n035\0'
    struct.pack_into('<IIIIII', buf, 32, len(buf), 112, 0x12345678, 0, 0, map_off)
    struct.pack_into('<IIIIIIIIIIIIII', buf, 56,
                     len(strings), string_ids, 3, type_ids, 1, proto_ids,
                     1, field_ids, 1, method_ids, 1, class_defs, len(buf) - data_off, data_off)
    buf[12:32] = hashlib.sha1(buf[32:]).digest()
    struct.pack_into('<I', buf, 8, zlib.adler32(buf[12:]) & 0xffffffff)
    return bytes(buf)


def make_field_invoke_chain_dex():
    """Build run() with the bytecode equivalent of this.a.callToMethod()."""
    strings = [
        b'Lexample/Test;', b'Ljava/lang/Object;', b'Lexample/Target;', b'V',
        b'run', b'a', b'callToMethod',
    ]
    buf = bytearray(112)
    sections = [(0, 1, 0)]

    def section(kind, size, data, align=4):
        buf.extend(b'\0' * (-len(buf) % align))
        off = len(buf)
        sections.append((kind, size, off))
        buf.extend(data)
        return off

    string_ids = section(1, len(strings), bytes(4 * len(strings)))
    type_ids = section(2, 4, struct.pack('<IIII', 0, 1, 2, 3))
    proto_ids = section(3, 1, struct.pack('<III', 3, 3, 0))
    field_ids = section(4, 1, struct.pack('<HHI', 0, 2, 5))
    method_ids = section(5, 2, struct.pack('<HHIHHI', 0, 0, 4, 2, 0, 6))
    class_defs = section(6, 1, bytes(32))
    data_off = len(buf)
    string_data = b''.join(uleb(len(s)) + s + b'\0' for s in strings)
    off = section(0x2002, len(strings), string_data, align=1)
    for i, value in enumerate(strings):
        struct.pack_into('<I', buf, string_ids + 4 * i, off)
        off += len(uleb(len(value))) + len(value) + 1

    # iget-object v0, p0, field@0; invoke-virtual {v0}, method@1; return-void
    insns = b'\x54\x10\x00\x00\x6e\x10\x01\x00\x00\x00\x0e\x00'
    code = section(
        0x2001, 1, struct.pack('<HHHHII', 2, 1, 1, 0, 0, 6) + insns
    )
    class_data = section(
        0x2000, 1, b'\x00\x01\x01\x00' + b'\x00\x01' + b'\x00\x01' + uleb(code),
        align=1,
    )
    struct.pack_into('<IIIIIIII', buf, class_defs, 0, 1, 1, 0, 0xffffffff, 0, class_data, 0)
    buf.extend(b'\0' * (-len(buf) % 4))
    map_off = len(buf)
    sections.append((0x1000, 1, map_off))
    buf.extend(struct.pack('<I', len(sections)))
    for kind, count, offset in sections:
        buf.extend(struct.pack('<HHII', kind, 0, count, offset))
    buf[:8] = b'dex\n035\0'
    struct.pack_into('<IIIIII', buf, 32, len(buf), 112, 0x12345678, 0, 0, map_off)
    struct.pack_into('<IIIIIIIIIIIIII', buf, 56,
                     len(strings), string_ids, 4, type_ids, 1, proto_ids,
                     1, field_ids, 2, method_ids, 1, class_defs, len(buf) - data_off, data_off)
    buf[12:32] = hashlib.sha1(buf[32:]).digest()
    struct.pack_into('<I', buf, 8, zlib.adler32(buf[12:]) & 0xffffffff)
    return bytes(buf)


def make_static_field_dex():
    """Build a DEX whose static_values and sget field operand must agree."""
    strings = [b'Lexample/Statics;', b'Ljava/lang/Object;', b'I', b'FIRST', b'SECOND', b'getSecond']
    buf = bytearray(112)
    sections = [(0, 1, 0)]

    def section(kind, size, data, align=4):
        buf.extend(b'\0' * (-len(buf) % align))
        off = len(buf)
        sections.append((kind, size, off))
        buf.extend(data)
        return off

    string_ids = section(1, len(strings), bytes(4 * len(strings)))
    type_ids = section(2, 3, struct.pack('<III', 0, 1, 2))
    proto_ids = section(3, 1, struct.pack('<III', 2, 2, 0))
    field_ids = section(4, 2, struct.pack('<HHIHHI', 0, 2, 3, 0, 2, 4))
    method_ids = section(5, 1, struct.pack('<HHI', 0, 0, 5))
    class_defs = section(6, 1, bytes(32))
    data_off = len(buf)

    string_data_off = section(0x2002, len(strings),
                              b''.join(uleb(len(s)) + s + b'\0' for s in strings), align=1)
    off = string_data_off
    for i, value in enumerate(strings):
        struct.pack_into('<I', buf, string_ids + 4 * i, off)
        off += len(uleb(len(value))) + len(value) + 1

    # sget v0, field@1 (SECOND); return v0
    code = section(0x2001, 1, struct.pack('<HHHHII', 1, 0, 0, 0, 0, 3) + b'\x60\x00\x01\x00\x0f\x00')
    class_data = section(0x2000, 1, b'\x02\x00\x01\x00' + b'\x00\x09\x01\x09' + b'\x00\x09' + uleb(code), align=1)
    static_values = section(0x2005, 1, b'\x02\x04\x0b\x04\x16', align=1)
    struct.pack_into('<IIIIIIII', buf, class_defs, 0, 1, 1, 0, 0xffffffff, 0, class_data, static_values)

    buf.extend(b'\0' * (-len(buf) % 4))
    map_off = len(buf)
    sections.append((0x1000, 1, map_off))
    buf.extend(struct.pack('<I', len(sections)))
    for kind, count, offset in sections:
        buf.extend(struct.pack('<HHII', kind, 0, count, offset))

    buf[:8] = b'dex\n035\0'
    struct.pack_into('<IIIIII', buf, 32, len(buf), 112, 0x12345678, 0, 0, map_off)
    struct.pack_into('<IIIIIIIIIIIIII', buf, 56,
                     len(strings), string_ids, 3, type_ids, 1, proto_ids,
                     2, field_ids, 1, method_ids, 1, class_defs, len(buf) - data_off, data_off)
    buf[12:32] = hashlib.sha1(buf[32:]).digest()
    struct.pack_into('<I', buf, 8, zlib.adler32(buf[12:]) & 0xffffffff)
    return bytes(buf)
