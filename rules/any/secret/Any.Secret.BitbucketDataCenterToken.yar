// betterleaks v1.10.0's bitbucket-data-center-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_BitbucketDataCenterToken
{
    meta:
        description         = "Discovered a Bitbucket Data Center HTTP access token, risking unauthorized repository and project access."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "BitbucketDataCenterToken"
        severity            = "high"
        score               = 80
        id                  = "bitbucket-data-center-token"
        confidence          = "high"
        keyword             = "bbdc"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b(BBDC-[A-Za-z0-9+\/=]{32,})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
