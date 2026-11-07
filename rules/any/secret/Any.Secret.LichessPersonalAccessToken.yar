// betterleaks v1.10.0's lichess-personal-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_LichessPersonalAccessToken
{
    meta:
        description     = "Lichess personal access token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "LichessPersonalAccessToken"
        severity        = "high"
        score           = 80
        id              = "lichess-personal-access-token"
        confidence      = "high"
        keyword         = "lip_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(lip_[A-Za-z0-9_]{16,60})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
