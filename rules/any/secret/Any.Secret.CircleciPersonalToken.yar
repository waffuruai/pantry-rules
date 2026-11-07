// betterleaks v1.10.0's circleci-personal-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_CircleciPersonalToken
{
    meta:
        description         = "CircleCI personal access token."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "CircleciPersonalToken"
        severity            = "high"
        score               = 80
        id                  = "circleci-personal-token"
        confidence          = "high"
        keyword             = "ccipat_"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b(CCIPAT_[a-zA-Z0-9]{22}_[a-z0-9]{40})/  // gitleaks:allow

    condition:
        $secret
}
