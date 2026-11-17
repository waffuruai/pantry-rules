// betterleaks v1.10.0's val-town-api-token.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ValTownApiToken1
{
    meta:
        description     = "Val Town API token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ValTownApiToken1"
        severity        = "high"
        score           = 80
        id              = "val-town-api-token.1"
        confidence      = "high"
        keyword         = "vtwn_"
        skip_entropy_lt = "3.5"
        require_secret  = "^(?:[^0-9]*[0-9]){2}"  // gitleaks:allow

    strings:
        $secret = /\b(vtwn_[A-Za-z0-9_-]{20,80})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
