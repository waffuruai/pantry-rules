// betterleaks v1.10.0's gumroad-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GumroadAccessToken
{
    meta:
        description         = "Detected a Gumroad access token, which may expose Gumroad account and product data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "GumroadAccessToken"
        severity            = "high"
        score               = 80
        id                  = "gumroad-access-token"
        confidence          = "high"
        keyword             = "gumroad"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[gG][uU][mM][rR][oO][aA][dD])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((?:[A-Fa-f0-9]{64}|[a-zA-ZA-Za-z0-9-]{43}))(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
