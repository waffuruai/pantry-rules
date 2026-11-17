// betterleaks v1.10.0's twitter-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_TwitterAccessToken
{
    meta:
        description         = "Detected a Twitter Access Token, posing a risk of unauthorized account operations and social media data exposure."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "TwitterAccessToken"
        severity            = "high"
        score               = 80
        id                  = "twitter-access-token"
        confidence          = "high"
        keyword             = "twitter"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{15,25}-[A-Za-za-zA-Z0-9]{20,40})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
