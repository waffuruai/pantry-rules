// betterleaks v1.10.0's looker-client-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_LookerClientSecret
{
    meta:
        description         = "Found a Looker Client Secret, risking unauthorized access to a Looker account and exposing sensitive data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "LookerClientSecret"
        severity            = "medium"
        score               = 50
        id                  = "looker-client-secret"
        confidence          = "medium"
        keyword             = "looker"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[lL][oO][oO][kK][eE][rR])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{24})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
