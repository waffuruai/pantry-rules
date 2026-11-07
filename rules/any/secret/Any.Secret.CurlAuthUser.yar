// betterleaks v1.10.0's curl-auth-user rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_CurlAuthUser
{
    meta:
        description       = "Discovered a potential basic authorization token provided in a curl command, which could compromise the curl accessed resource."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "CurlAuthUser"
        severity          = "high"
        score             = 80
        id                = "curl-auth-user"
        confidence        = "high"
        keyword           = "curl"
        skip_entropy_le   = "2.0"
        skip_regex_secret = "[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\\*+|x+)"  // gitleaks:allow
        skip_regex_secret = "['\"]?<[^>]+>['\"]?:['\"]?<[^>]+>|<[^:]+:[^>]+>['\"]?"  // gitleaks:allow
        skip_regex_secret = "[^:]+:\\[[^]]+]"  // gitleaks:allow
        skip_regex_secret = "['\"]?[^:]+['\"]?:['\"]?\\$(?:\\d|\\w+|\\{(?:\\d|\\w+)})['\"]?"  // gitleaks:allow
        skip_regex_secret = "['\"]?\\$\\{(?:[^{}]|\\{[^}]*\\})*\\}['\"]?:['\"]?\\$\\{(?:[^{}]|\\{[^}]*\\})*\\}['\"]?"  // gitleaks:allow
        skip_regex_secret = "\\$\\([^)]+\\):\\$\\([^)]+\\)"  // gitleaks:allow
        skip_regex_secret = "['\"]?\\$?{{[^}]+}}['\"]?:['\"]?\\$?{{[^}]+}}['\"]?"  // gitleaks:allow

    strings:
        $secret = /\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|'([^:']{3,}:[^']{3,})'|((?:"[^"]{3,}"|'[^']{3,}'|[\w$@.-]+):(?:"[^"]{3,}"|'[^']{3,}'|[\w$\{\}@.-]+)))(?:\s|$)/  // gitleaks:allow

    condition:
        $secret
}
