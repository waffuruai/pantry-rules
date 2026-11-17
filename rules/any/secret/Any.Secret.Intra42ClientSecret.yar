// betterleaks v1.10.0's intra42-client-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_Intra42ClientSecret
{
    meta:
        description     = "Found a Intra42 client secret, which could lead to unauthorized access to the 42School API and sensitive data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "Intra42ClientSecret"
        severity        = "high"
        score           = 80
        id              = "intra42-client-secret"
        confidence      = "high"
        keyword         = "intra"
        keyword         = "s-s4t2ud-"
        keyword         = "s-s4t2af-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(s-s4t2(?:ud|af)-[ABCDEFabcdef0123456789]{64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
