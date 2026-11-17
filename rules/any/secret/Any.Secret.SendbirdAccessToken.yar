// betterleaks v1.10.0's sendbird-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SendbirdAccessToken
{
    meta:
        description         = "Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "SendbirdAccessToken"
        severity            = "high"
        score               = 80
        id                  = "sendbird-access-token"
        confidence          = "high"
        keyword             = "sendbird"
        skip_entropy_lt     = "3.3"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[sS][eE][nN][dD][bB][iI][rR][dD])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{40})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
