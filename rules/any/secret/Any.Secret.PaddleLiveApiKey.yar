// betterleaks v1.10.0's paddle-live-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PaddleLiveApiKey
{
    meta:
        description     = "Paddle live API key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PaddleLiveApiKey"
        severity        = "high"
        score           = 80
        id              = "paddle-live-api-key"
        confidence      = "high"
        keyword         = "pdl_live_apikey_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(pdl_live_apikey_[a-z0-9]{26}_[A-Za-z0-9]{22}_[A-Za-z0-9]{3})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
