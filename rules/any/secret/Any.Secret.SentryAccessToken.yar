// betterleaks v1.10.0's sentry-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SentryAccessToken
{
    meta:
        description         = "Found a Sentry.io Access Token (old format), risking unauthorized access to error tracking services and sensitive application data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "SentryAccessToken"
        severity            = "medium"
        score               = 50
        id                  = "sentry-access-token"
        confidence          = "medium"
        keyword             = "sentry"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[sS][eE][nN][tT][rR][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
