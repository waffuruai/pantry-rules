// betterleaks v1.10.0's onfido-live-api-token-us rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_OnfidoLiveApiTokenUs
{
    meta:
        description     = "Onfido live API token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "OnfidoLiveApiTokenUs"
        severity        = "high"
        score           = 80
        id              = "onfido-live-api-token-us"
        confidence      = "high"
        keyword         = "api_live_us."
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(api_live_us\.[A-Za-z0-9_-]{20,80})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
