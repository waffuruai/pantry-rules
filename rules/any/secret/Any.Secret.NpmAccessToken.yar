// betterleaks v1.10.0's npm-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_NpmAccessToken
{
    meta:
        description     = "Uncovered an npm access token, potentially compromising package management and code repository access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "NpmAccessToken"
        severity        = "high"
        score           = 80
        id              = "npm-access-token"
        confidence      = "high"
        keyword         = "npm_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\b([nN][pP][mM]_[A-Za-z0-9]{36})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
