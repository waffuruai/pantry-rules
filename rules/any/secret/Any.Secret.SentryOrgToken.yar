// betterleaks v1.10.0's sentry-org-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SentryOrgToken
{
    meta:
        description         = "Found a Sentry.io Organization Token, risking unauthorized access to error tracking services and sensitive application data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "SentryOrgToken"
        severity            = "high"
        score               = 80
        id                  = "sentry-org-token"
        confidence          = "high"
        keyword             = "sntrys_eyjpyxqio"
        skip_entropy_lt     = "4.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\bsntrys_eyJpYXQiO[a-zA-Z0-9+\/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+\/]{10,200}={0,2}_[a-zA-Z0-9+\/]{43}(?:[^a-zA-Z0-9+\/]|$)/  // gitleaks:allow

    condition:
        $secret
}
