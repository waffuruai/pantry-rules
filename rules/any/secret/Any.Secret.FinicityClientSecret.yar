// betterleaks v1.10.0's finicity-client-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_FinicityClientSecret
{
    meta:
        description         = "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "FinicityClientSecret"
        severity            = "high"
        score               = 80
        id                  = "finicity-client-secret"
        confidence          = "high"
        keyword             = "finicity"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[fF][iI][nN][iI][cC][iI][tT][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{20})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
