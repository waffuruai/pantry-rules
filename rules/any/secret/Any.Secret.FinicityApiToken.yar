// betterleaks v1.10.0's finicity-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_FinicityApiToken
{
    meta:
        description         = "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "FinicityApiToken"
        severity            = "high"
        score               = 80
        id                  = "finicity-api-token"
        confidence          = "high"
        keyword             = "finicity"
        skip_entropy_lt     = "3.3"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[fF][iI][nN][iI][cC][iI][tT][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
