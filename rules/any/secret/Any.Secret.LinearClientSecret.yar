// betterleaks v1.10.0's linear-client-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_LinearClientSecret
{
    meta:
        description         = "Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "LinearClientSecret"
        severity            = "medium"
        score               = 50
        id                  = "linear-client-secret"
        confidence          = "medium"
        keyword             = "linear"
        skip_entropy_lt     = "3.3"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[lL][iI][nN][eE][aA][rR])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
