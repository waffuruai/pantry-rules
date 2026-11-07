// betterleaks v1.10.0's facebook-page-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_FacebookPageAccessToken
{
    meta:
        description         = "Discovered a Facebook Page Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "FacebookPageAccessToken"
        severity            = "high"
        score               = 80
        id                  = "facebook-page-access-token"
        confidence          = "high"
        keyword             = "eaam"
        keyword             = "eaac"
        skip_entropy_lt     = "4.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b(EAA[MC][A-Za-z0-9]{100,})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
