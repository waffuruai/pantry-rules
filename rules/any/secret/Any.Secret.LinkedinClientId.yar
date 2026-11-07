// betterleaks v1.10.0's linkedin-client-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_LinkedinClientId
{
    meta:
        description         = "Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "LinkedinClientId"
        severity            = "medium"
        score               = 50
        id                  = "linkedin-client-id"
        confidence          = "medium"
        keyword             = "linkedin"
        keyword             = "linked_in"
        keyword             = "linked-in"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[lL][iI][nN][kK][eE][dD][_-]?[iI][nN])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{14})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
