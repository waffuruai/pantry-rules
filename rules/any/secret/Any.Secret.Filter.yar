// betterleaks v1.10.0's global filter (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// It never matches: the scanner reads its meta.

private rule Any_Secret_Filter
{
    meta:
        description       = "betterleaks' global filter: secrets Pantry never reports, whatever rule finds them"
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        skip_regex_secret = "(?i)^true|false|null$"  // gitleaks:allow
        skip_regex_secret = "^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$"  // gitleaks:allow
        skip_regex_secret = "^\\$(?:\\d+|{\\d+})$"  // gitleaks:allow
        skip_regex_secret = "^\\$(?:[A-Z_]+|[a-z_]+)$"  // gitleaks:allow
        skip_regex_secret = "^\\${(?:[A-Z_]+|[a-z_]+)}$"  // gitleaks:allow
        skip_regex_secret = "^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$"  // gitleaks:allow
        skip_regex_secret = "^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}$"  // gitleaks:allow
        skip_regex_secret = "^%(?:[A-Z_]+|[a-z_]+)%$"  // gitleaks:allow
        skip_regex_secret = "^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$"  // gitleaks:allow
        skip_regex_secret = "^\\{\\d{0,2}}$"  // gitleaks:allow
        skip_regex_secret = "^@(?:[A-Z_]+|[a-z_]+)@$"  // gitleaks:allow
        skip_regex_secret = "^/Users/(?i)[a-z0-9]+/[\\w .-/]+$"  // gitleaks:allow
        skip_regex_secret = "^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$"  // gitleaks:allow
        skip_word_secret  = "abcdefghijklmnopqrstuvwxyz"  // gitleaks:allow
        skip_word_secret  = "014df517-39d1-4453-b7b3-9930c563627c"  // gitleaks:allow

    condition:
        false
}
