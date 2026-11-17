// betterleaks v1.10.0's travisci-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_TravisciAccessToken
{
    meta:
        description         = "Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "TravisciAccessToken"
        severity            = "medium"
        score               = 50
        id                  = "travisci-access-token"
        confidence          = "medium"
        keyword             = "travis"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[tT][rR][aA][vV][iI][sS])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{22})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
