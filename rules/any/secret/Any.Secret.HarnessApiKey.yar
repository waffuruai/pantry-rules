// betterleaks v1.10.0's harness-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_HarnessApiKey
{
    meta:
        description     = "Identified a Harness Access Token (PAT or SAT), risking unauthorized access to a Harness account."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "HarnessApiKey"
        severity        = "high"
        score           = 80
        id              = "harness-api-key"
        confidence      = "high"
        keyword         = "pat."
        keyword         = "sat."
        skip_entropy_le = "3.4"

    strings:
        $secret = /(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[0-9a-f]{24}\.[a-zA-Z0-9]{20}/  // gitleaks:allow

    condition:
        $secret
}
