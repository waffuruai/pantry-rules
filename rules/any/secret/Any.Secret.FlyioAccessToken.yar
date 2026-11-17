// betterleaks v1.10.0's flyio-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_FlyioAccessToken
{
    meta:
        description     = "Uncovered a Fly.io API key"
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "FlyioAccessToken"
        severity        = "high"
        score           = 80
        id              = "flyio-access-token"
        confidence      = "high"
        keyword         = "flyv1"
        skip_entropy_le = "4.0"

    strings:
        $secret = /\b(FlyV1\s[A-Za-z0-9=_\-,\/+]{100,})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
