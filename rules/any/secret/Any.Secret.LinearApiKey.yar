// betterleaks v1.10.0's linear-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_LinearApiKey
{
    meta:
        description         = "Detected a Linear API Token, posing a risk to project management tools and sensitive task data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "LinearApiKey"
        severity            = "high"
        score               = 80
        id                  = "linear-api-key"
        confidence          = "high"
        keyword             = "lin_api_"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /lin_api_[A-Za-z0-9]{40}/  // gitleaks:allow

    condition:
        $secret
}
