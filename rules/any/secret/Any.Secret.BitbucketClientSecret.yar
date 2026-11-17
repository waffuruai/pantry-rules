// betterleaks v1.10.0's bitbucket-client-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_BitbucketClientSecret
{
    meta:
        description         = "Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "BitbucketClientSecret"
        severity            = "high"
        score               = 80
        id                  = "bitbucket-client-secret"
        confidence          = "high"
        keyword             = "bitbucket"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[bB][iI][tT][bB][uU][cC][kK][eE][tT])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9=_\-]{64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
