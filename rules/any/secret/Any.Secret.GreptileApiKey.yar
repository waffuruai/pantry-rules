// betterleaks v1.10.0's greptile-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_GreptileApiKey
{
    meta:
        description         = "Detected a Greptile API Key, which may expose AI-powered code search and analysis services to unauthorized access."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "GreptileApiKey"
        severity            = "high"
        score               = 80
        id                  = "greptile-api-key"
        confidence          = "high"
        keyword             = "greptile"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[gG][rR][eE][pP][tT][iI][lL][eE])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-za-zA-Z0-9+\/]{48})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
