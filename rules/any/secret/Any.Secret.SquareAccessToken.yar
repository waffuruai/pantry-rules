// betterleaks v1.10.0's square-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SquareAccessToken
{
    meta:
        description     = "Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SquareAccessToken"
        severity        = "high"
        score           = 80
        id              = "square-access-token"
        confidence      = "high"
        keyword         = "sq0atp-"
        keyword         = "eaaa"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\b((?:EAAA|sq0atp-)[\w-]{22,60})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
