// betterleaks v1.10.0's samsara-api-token.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_SamsaraApiToken1
{
    meta:
        description     = "Samsara API token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SamsaraApiToken1"
        severity        = "high"
        score           = 80
        id              = "samsara-api-token.1"
        confidence      = "high"
        keyword         = "samsara_api_"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(samsara_api_[A-Za-z0-9]{26,32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
