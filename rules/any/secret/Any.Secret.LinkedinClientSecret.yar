// betterleaks v1.10.0's linkedin-client-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_LinkedinClientSecret
{
    meta:
        description         = "Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "LinkedinClientSecret"
        severity            = "medium"
        score               = 50
        id                  = "linkedin-client-secret"
        confidence          = "medium"
        keyword             = "linkedin"
        keyword             = "linked_in"
        keyword             = "linked-in"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[lL][iI][nN][kK][eE][dD][_-]?[iI][nN])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{16})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
