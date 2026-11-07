import re
import unittest

import betterleaks as bl


class FoldTests(unittest.TestCase):
    def test_a_leading_case_flag_folds_every_letter(self):
        self.assertEqual(bl.fold("(?i)ab1"), "[aA][bB]1")

    def test_a_scoped_flag_folds_only_its_group(self):
        self.assertEqual(bl.fold("x(?i:y)z"), "x(?:[yY])z")

    def test_a_scoped_unset_flag_stops_folding_inside_its_group(self):
        self.assertEqual(bl.fold("(?i)a(?-i:B)c"), "[aA](?:B)[cC]")

    def test_a_folded_class_puts_its_swapped_letters_first(self):
        # so a trailing `-` stays a literal, not a range
        self.assertEqual(bl.fold("(?i)[a-z_-]"), "[A-Za-z_-]")

    def test_escapes_stay_and_go_anchors_become_yara_anchors(self):
        self.assertEqual(bl.fold(r"(?i)\d\w\x60\z"), r"\d\w\x60$")

    def test_slashes_and_literal_braces_are_escaped(self):
        self.assertEqual(bl.fold("a/b{c}{2,3}"), r"a\/b\{c\}{2,3}")

    def test_posix_classes_are_spelled_out_and_named_groups_lose_names(self):
        self.assertEqual(bl.fold("[[:alnum:]](?P<k>x)"), "[A-Za-z0-9](x)")

    def test_folded_patterns_match_what_the_flags_matched(self):
        for src, text in [("(?i)api(?-i:KEY)", "ApIKEY"), ("(?i)[a-f]{3}", "aBc"), ("x(?i:y)", "xY")]:
            self.assertTrue(re.fullmatch(bl.fold(src), text), src)
        self.assertFalse(re.fullmatch(bl.fold("(?i)api(?-i:KEY)"), "apikey"))

    def test_lookarounds_are_refused(self):
        with self.assertRaises(bl.Unsupported):
            bl.fold("a(?=b)")


class FilterTests(unittest.TestCase):
    def test_entropy_and_token_ratio_become_skip_thresholds(self):
        meta = bl.flat(bl.filter_meta('filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5'))
        self.assertEqual(meta, [("skip_entropy_lt", '"3.5"'), ("skip_token_ratio_ge", '"2.5"')])

    def test_at_most_is_kept_apart_from_less_than(self):
        self.assertEqual(bl.flat(bl.filter_meta('entropy(finding["secret"]) <= 3')), [("skip_entropy_le", '"3.0"')])

    def test_lists_become_one_entry_per_pattern_or_word(self):
        meta = bl.flat(bl.filter_meta('matchesAny(attributes["path"], [`a/b`, `(?i)c`]) || containsAny(finding["line"], ["x"])'))
        self.assertEqual(meta, [("skip_regex_path", '"a/b"'), ("skip_regex_path", '"(?i)c"'), ("skip_word_line", '"x"')])

    def test_a_negated_match_is_a_requirement(self):
        meta = bl.flat(bl.filter_meta('!filter.matchesAny(finding["secret"], ["[0-9]", "[A-Z]"])'))
        self.assertEqual(meta, [("require_secret", '"(?:[0-9])|(?:[A-Z])"')])

    def test_comments_and_parentheses_are_read(self):
        meta = bl.flat(bl.filter_meta('// why\n(entropy(finding["secret"]) <= 2.0\n|| containsAny(finding["secret"], ["a"]))'))
        self.assertEqual(meta, [("skip_entropy_le", '"2.0"'), ("skip_word_secret", '"a"')])

    def test_programs_and_conjunctions_are_left_to_built_ins(self):
        for src in ['let x = 1; x', 'entropy(finding["secret"]) < 3 && containsAny(finding["secret"], ["a"])',
                    'entropy(finding["match"]) < 3', 'matchesAny(finding["fragment_raw"], ["a"])']:
            with self.assertRaises(bl.Unsupported, msg=src):
                bl.filter_meta(src)


class RuleTests(unittest.TestCase):
    RULE = {"id": "acme-key.1", "description": 'Acme "key"', "confidence": "medium", "keywords": ["acme_"],
            "regex": r"(?i)\bacme_([a-z0-9]{8})\b", "filter": 'entropy(finding["secret"]) <= 3',
            "components": [{"id": "acme-id", "within": "5L"}, {"id": "acme-region", "optional": True}],
            "validate": "http.get(...)"}

    def test_a_rule_carries_its_regex_meta_and_components(self):
        name, text = bl.rule_text(self.RULE)
        self.assertEqual(name, "AcmeKey1")
        self.assertIn("rule Any_Secret_AcmeKey1\n", text)
        self.assertIn(r"$secret = /\b[aA][cC][mM][eE]_([A-Za-z0-9]{8})\b/", text)
        for line in ['id               = "acme-key.1"', 'severity         = "medium"', 'keyword          = "acme_"',
                     'description      = "Acme \\"key\\""', 'component1       = "acme-id"',
                     'component1_within = "5L"', 'component2_optional = true', 'skip_entropy_le  = "3.0"']:
            self.assertIn(" ".join(line.split()), " ".join(text.split()))
        self.assertIn("issues/190", text)

    def test_a_component_only_rule_is_private(self):
        _, text = bl.rule_text({**self.RULE, "skipReport": True})
        self.assertIn("private rule Any_Secret_AcmeKey1", text)

    def test_a_program_filter_is_kept_as_written_in_meta_and_a_comment(self):
        _, text = bl.rule_text({**self.RULE, "filter": "let a = 1;\na > 0"})
        self.assertIn('filter_expr = "let a = 1;\\na > 0"', " ".join(text.split()).replace("filter_expr =", "filter_expr ="))
        self.assertIn("// let a = 1;\n// a > 0", text)

    def test_a_path_rule_matches_on_filepath(self):
        _, text = bl.rule_text({"id": "p12", "description": "d", "path": r"(?i)\.p12$"})
        self.assertIn(r"filepath matches /\.[pP]12$/", text)
        self.assertNotIn("strings:", text)

    def test_meta_strings_escape_quotes_backslashes_and_controls(self):
        self.assertEqual(bl.meta_str('a"b\\c\nd\x01é'), r'"a\"b\\c\nd\x01\xc3\xa9"')


class CaseTests(unittest.TestCase):
    def test_samples_match_the_regex_they_come_from(self):
        import random
        for src in [r"\b(AKIA[A-Z2-7]{16})\b", r"(?i)token[=:]\s*([a-f0-9]{32})", r"x(?:ab|cd){2,}y"]:
            folded = bl.fold(src)
            parsed = bl.P.parse(folded)
            rng = random.Random(1)
            for _ in range(20):
                self.assertTrue(re.search(folded, bl.sample(rng, parsed)), src)

    def test_a_case_needs_the_rule_alone_and_its_secret_once(self):
        rule = {"id": "r"}
        self.assertEqual(bl.accepted(rule, "k=abc\n", [("r", "abc", 1)]), "abc")
        self.assertIsNone(bl.accepted(rule, "k=abc\n", [("r", "abc", 1), ("generic-api-key", "abc", 1)]))
        self.assertIsNone(bl.accepted(rule, "abc abc\n", [("r", "abc", 1)]))
        self.assertIsNone(bl.accepted(rule, "k=abc\n", []))


class CatalogueTests(unittest.TestCase):
    def test_a_shape_keeps_the_prefix_and_masks_the_rest_by_class(self):
        self.assertEqual(bl.shape("ghp_aB3-x9"), "ghp_‹3›-‹2›")
        self.assertEqual(bl.shape("A3-IT8EV3-WY81"), "A3-I‹5›-‹4›")
        self.assertEqual(bl.shape("abcd"), "abcd")


if __name__ == "__main__":
    unittest.main()
