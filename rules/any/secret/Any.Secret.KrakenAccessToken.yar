// betterleaks v1.10.0's kraken-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_KrakenAccessToken
{
    meta:
        description         = "Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "KrakenAccessToken"
        severity            = "medium"
        score               = 50
        id                  = "kraken-access-token"
        confidence          = "medium"
        keyword             = "kraken"
        skip_entropy_lt     = "4.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[kK][rR][aA][kK][eE][nN])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9\/=_\+\-]{80,90})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
