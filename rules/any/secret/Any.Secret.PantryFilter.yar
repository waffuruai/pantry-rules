// Waffuru's secret filters: what Pantry skips beyond betterleaks' own filters. They never
// match; the scanner reads their meta, with the keys tools/betterleaks.py documents, plus
// `applies_to` (repeated): the rule ids a filter is limited to (none: every rule). A meta
// regex may start with `(?i)` to ignore case.

private rule Any_Secret_PantryFilter_GenericIdentifiers
{
    meta:
        description      = "Hashes, ids and names the generic rule mistakes for keys"
        author           = "Waffuru"
        reference        = "https://github.com/waffuruai/pantry/issues/44"
        os               = "any"
        category         = "secret"
        applies_to       = "generic-api-key"
        skip_regex_secret = "^[0-9a-fA-F]{16,}$"
        skip_regex_secret = "(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        skip_regex_secret = "^[A-Z][A-Z0-9_]+$"
        skip_regex_secret = "^[a-z][a-z0-9]*([._\\/-][a-z0-9]+)+$"

    condition:
        false
}

private rule Any_Secret_PantryFilter_TestVectors
{
    meta:
        description     = "Known-answer tests and fixtures: keys there are published on purpose"
        author          = "Waffuru"
        reference       = "https://github.com/waffuruai/pantry/issues/44"
        os              = "any"
        category        = "secret"
        applies_to      = "generic-api-key"
        skip_regex_path = "(?i)(^|\\/)(test[-_]?vectors?|testvectors|testdata|fixtures?|__fixtures__|kat|vectors|golden)(\\/|$)"
        skip_regex_path = "(?i)\\.(rsp|kat|tv|vec)$"
        skip_regex_path = "(?i)(^|\\/)(cryptopp|supercop|wycheproof)\\/"

    condition:
        false
}

private rule Any_Secret_PantryFilter_Placeholders
{
    meta:
        description       = "Placeholders in docs and examples, in one case: a mixed-case value is a key, not a placeholder"
        author            = "Waffuru"
        reference         = "https://github.com/waffuruai/pantry/issues/44"
        os                = "any"
        category          = "secret"
        skip_regex_secret = "^(your|my|example|sample|dummy|fake|placeholder|changeme|xxx+)[-_a-z0-9]*$"
        skip_regex_secret = "^(YOUR|MY|EXAMPLE|SAMPLE|DUMMY|FAKE|PLACEHOLDER|CHANGEME|XXX+)[-_A-Z0-9]*$"
        skip_regex_secret = "^<[^>]+>$"
        skip_regex_secret = "^\\$\\{?([A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*)\\}?$"

    condition:
        false
}
