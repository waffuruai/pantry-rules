// betterleaks v1.10.0's adafruit-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_AdafruitApiKey
{
    meta:
        description         = "Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "AdafruitApiKey"
        severity            = "high"
        score               = 80
        id                  = "adafruit-api-key"
        confidence          = "high"
        keyword             = "adafruit"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[aA][dD][aA][fF][rR][uU][iI][tT])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
