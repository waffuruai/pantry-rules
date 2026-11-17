// betterleaks v1.10.0's kucoin-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_KucoinAccessToken
{
    meta:
        description         = "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "KucoinAccessToken"
        severity            = "high"
        score               = 80
        id                  = "kucoin-access-token"
        confidence          = "high"
        keyword             = "kucoin"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[kK][uU][cC][oO][iI][nN])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{24})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
