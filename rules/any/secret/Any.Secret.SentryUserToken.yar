// betterleaks v1.10.0's sentry-user-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SentryUserToken
{
    meta:
        description         = "Found a Sentry.io User Token, risking unauthorized access to error tracking services and sensitive application data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "SentryUserToken"
        severity            = "high"
        score               = 80
        id                  = "sentry-user-token"
        confidence          = "high"
        keyword             = "sntryu_"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b(sntryu_[a-f0-9]{64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
