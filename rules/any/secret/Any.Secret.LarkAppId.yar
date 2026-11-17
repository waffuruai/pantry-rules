// betterleaks v1.10.0's lark-app-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_LarkAppId
{
    meta:
        description         = "Lark application ID, used as a component of the Lark application-secret rule."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "LarkAppId"
        severity            = "high"
        score               = 80
        id                  = "lark-app-id"
        confidence          = "high"
        keyword             = "cli_"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b(cli_[A-Za-z0-9]{16})/  // gitleaks:allow

    condition:
        $secret
}
