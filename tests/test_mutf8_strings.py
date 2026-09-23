import base64
import struct
import unittest

from droidasc.asc_core.utils.tinydex import DEX, _decode_mutf8_fallback


ISSUE_DEX = base64.b64decode(
    "ZGV4CjAzNQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADtAAAAcAAAAHhWNBIAAAAAAAAA"
    "AAAAAAADAAAAcAAAAAMAAAB8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAIgA"
    "AAAAAAAAAAAAAMgAAADcAAAA5AAAAAAAAAABAAAAAgAAAAEAAAABAAAAAAAAAAAAAAD/"
    "////AAAAAAAAAAAAAAAAAgAAAAEAAAAAAAAAAAAAAP////8AAAAAAAAAAAAAAAASTGph"
    "dmEvbGFuZy9PYmplY3Q7AAVMbC/boTsABUxsL+GpuzsA"
)


def _uleb128(value):
    out = bytearray()
    while value > 0x7f:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return out


def _encode_mutf8(text):
    out = bytearray()
    utf16 = text.encode("utf-16-be")
    for offset in range(0, len(utf16), 2):
        unit = int.from_bytes(utf16[offset:offset + 2], "big")
        if unit == 0:
            out.extend(b"\xc0\x80")
        elif unit <= 0x7f:
            out.append(unit)
        elif unit <= 0x7ff:
            out.extend((0xc0 | (unit >> 6), 0x80 | (unit & 0x3f)))
        else:
            out.extend((
                0xe0 | (unit >> 12),
                0x80 | ((unit >> 6) & 0x3f),
                0x80 | (unit & 0x3f),
            ))
    return bytes(out)


def _make_class_dex(names):
    encoded = [_encode_mutf8(name) for name in names]
    units = [len(name.encode("utf-16-le")) // 2 for name in names]
    buf = bytearray(0x70)

    string_ids_off = len(buf)
    buf.extend(bytes(4 * len(names)))
    type_ids_off = len(buf)
    buf.extend(bytes(4 * len(names)))
    class_defs_off = len(buf)
    buf.extend(bytes(32 * len(names)))
    data_off = len(buf)

    for index, (raw, utf16_size) in enumerate(zip(encoded, units)):
        struct.pack_into("<I", buf, string_ids_off + index * 4, len(buf))
        struct.pack_into("<I", buf, type_ids_off + index * 4, index)
        struct.pack_into(
            "<IIIIIIII",
            buf,
            class_defs_off + index * 32,
            index,
            1,
            0xffffffff,
            0,
            0xffffffff,
            0,
            0,
            0,
        )
        buf.extend(_uleb128(utf16_size))
        buf.extend(raw)
        buf.append(0)

    buf[:8] = b"dex\n035\0"
    struct.pack_into("<IIIIII", buf, 0x20, len(buf), 0x70, 0x12345678, 0, 0, 0)
    struct.pack_into(
        "<IIIIIIIIIIIIII",
        buf,
        0x38,
        len(names),
        string_ids_off,
        len(names),
        type_ids_off,
        0,
        0,
        0,
        0,
        0,
        0,
        len(names),
        class_defs_off,
        len(buf) - data_off,
        data_off,
    )
    return bytes(buf)


class Mutf8StringTests(unittest.TestCase):
    def test_issue_fixture_decodes_and_finds_non_ascii_classes(self):
        dex = DEX.parse(ISSUE_DEX, "bug.dex")

        self.assertEqual([dex.get_string(i) for i in range(3)], [
            "Ljava/lang/Object;",
            "Ll/\u06e1;",
            "Ll/\u1a7b;",
        ])
        self.assertIsNotNone(dex.get_class("Ll/\u06e1;"))
        self.assertIsNotNone(dex.get_class("Ll/\u1a7b;"))

    def test_mutf8_special_forms_decode(self):
        self.assertEqual(_decode_mutf8_fallback(b"a\xc0\x80b"), "a\x00b")
        self.assertEqual(
            _decode_mutf8_fallback(b"\xed\xa0\xbd\xed\xb8\x80"),
            "\U0001f600",
        )

    def test_malformed_mutf8_uses_replacement_character(self):
        self.assertEqual(_decode_mutf8_fallback(b"a\xffb"), "a\ufffdb")

    def test_get_class_falls_back_for_utf16_sort_order(self):
        names = ["Ll/\U00010000;", "Ll/\ue000;"]
        dex = DEX.parse(_make_class_dex(names), "utf16-order.dex")

        for name in names:
            with self.subTest(name=name):
                self.assertIsNotNone(dex.get_class(name))

    def test_unterminated_string_is_rejected(self):
        data = bytearray(_make_class_dex(["Lexample/Test;"]))
        data[-1] = 1
        dex = DEX.parse(data, "unterminated.dex")

        with self.assertRaisesRegex(ValueError, "unterminated string_data_item"):
            dex.get_string(0)


if __name__ == "__main__":
    unittest.main()
