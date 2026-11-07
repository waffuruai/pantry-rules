// betterleaks v1.10.0's coveralls-personal-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_CoverallsPersonalApiToken
{
    meta:
        description         = "Detected a Coveralls personal API token, which may expose repository coverage data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "CoverallsPersonalApiToken"
        severity            = "medium"
        score               = 50
        id                  = "coveralls-personal-api-token"
        confidence          = "medium"
        keyword             = "coveralls"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[cC][oO][vV][eE][rR][aA][lL][lL][sS])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-ZA-Za-z0-9-]{37})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
