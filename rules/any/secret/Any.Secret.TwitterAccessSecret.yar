// betterleaks v1.10.0's twitter-access-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_TwitterAccessSecret
{
    meta:
        description         = "Uncovered a Twitter Access Secret, potentially risking unauthorized Twitter integrations and data breaches."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "TwitterAccessSecret"
        severity            = "high"
        score               = 80
        id                  = "twitter-access-secret"
        confidence          = "high"
        keyword             = "twitter"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{45})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
