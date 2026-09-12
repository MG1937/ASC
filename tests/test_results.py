import unittest

from dex_fixture import make_dex
from src.asc_client.asc_handler import AscHandler
from src.asc_client.results import FindRefHit, format_findref_hit


class ResultsTests(unittest.TestCase):
    def test_findrefs_hits_on_make_dex(self):
        hits = AscHandler().findrefs_hits(
            'fixture.dex', make_dex(), 'string', {'string': 'token'}
        )
        self.assertEqual(
            hits,
            [
                FindRefHit(
                    dex_name='fixture.dex',
                    caller_class='Lexample/Test;',
                    caller_method='first',
                    matched=('token',),
                ),
                FindRefHit(
                    dex_name='fixture.dex',
                    caller_class='Lexample/Test;',
                    caller_method='second',
                    matched=('token',),
                ),
            ],
        )

    def test_text_formatter_matches_existing_lines(self):
        hits = AscHandler().findrefs_hits(
            'fixture.dex', make_dex(), 'string', {'string': 'token'}
        )
        lines = [format_findref_hit(hit) for hit in hits]
        self.assertEqual(
            lines,
            [
                'fixture.dex | Lexample/Test;->first | matched=(token)',
                'fixture.dex | Lexample/Test;->second | matched=(token)',
            ],
        )
        self.assertEqual(
            AscHandler().findrefs('fixture.dex', make_dex(), 'string', {'string': 'token'}),
            lines,
        )


if __name__ == '__main__':
    unittest.main()
