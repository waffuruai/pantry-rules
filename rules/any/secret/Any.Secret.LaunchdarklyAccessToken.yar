// betterleaks v1.10.0's launchdarkly-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_LaunchdarklyAccessToken
{
    meta:
        description         = "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "LaunchdarklyAccessToken"
        severity            = "high"
        score               = 80
        id                  = "launchdarkly-access-token"
        confidence          = "high"
        keyword             = "launchdarkly"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[lL][aA][uU][nN][cC][hH][dD][aA][rR][kK][lL][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9=_\-]{40})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
