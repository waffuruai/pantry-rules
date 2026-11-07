// betterleaks v1.10.0's privateai-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_PrivateaiApiToken
{
    meta:
        description         = "Identified a PrivateAI Token, posing a risk of unauthorized access to AI services and data manipulation."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "PrivateaiApiToken"
        severity            = "medium"
        score               = 50
        id                  = "privateai-api-token"
        confidence          = "medium"
        keyword             = "privateai"
        keyword             = "private_ai"
        keyword             = "private-ai"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:(?:[pP][rR][iI][vV][aA][tT][eE][_-]?[aA][iI])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
