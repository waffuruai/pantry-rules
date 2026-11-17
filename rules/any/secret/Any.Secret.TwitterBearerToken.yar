// betterleaks v1.10.0's twitter-bearer-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_TwitterBearerToken
{
    meta:
        description         = "Discovered a Twitter Bearer Token, potentially compromising API access and data retrieval from Twitter."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "TwitterBearerToken"
        severity            = "high"
        score               = 80
        id                  = "twitter-bearer-token"
        confidence          = "high"
        keyword             = "twitter"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([Aa]{22}[A-Za-za-zA-Z0-9%]{80,100})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
