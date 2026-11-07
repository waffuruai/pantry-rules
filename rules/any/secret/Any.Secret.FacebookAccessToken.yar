// betterleaks v1.10.0's facebook-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_FacebookAccessToken
{
    meta:
        description         = "Discovered a Facebook Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "FacebookAccessToken"
        severity            = "high"
        score               = 80
        id                  = "facebook-access-token"
        confidence          = "high"
        keyword             = "facebook"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b(\d{15,16}(\||%)[A-Z0-9a-z\-_]{27,40})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
