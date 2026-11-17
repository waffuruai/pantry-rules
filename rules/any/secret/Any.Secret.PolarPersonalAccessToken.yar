// betterleaks v1.10.0's polar-personal-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PolarPersonalAccessToken
{
    meta:
        description     = "Polar personal access token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PolarPersonalAccessToken"
        severity        = "high"
        score           = 80
        id              = "polar-personal-access-token"
        confidence      = "high"
        keyword         = "polar_pat_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(polar_pat_[A-Za-z0-9_-]{20,100})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
