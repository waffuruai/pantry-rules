// betterleaks v1.10.0's facebook-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_FacebookSecret
{
    meta:
        description         = "Discovered a Facebook Application secret, posing a risk of unauthorized access to Facebook accounts and personal data exposure."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "FacebookSecret"
        severity            = "high"
        score               = 80
        id                  = "facebook-secret"
        confidence          = "high"
        keyword             = "facebook"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[fF][aA][cC][eE][bB][oO][oO][kK])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
