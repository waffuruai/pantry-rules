// betterleaks v1.10.0's shopify-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ShopifyAccessToken
{
    meta:
        description     = "Uncovered a Shopify access token, which could lead to unauthorized e-commerce platform access and data breaches."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ShopifyAccessToken"
        severity        = "high"
        score           = 80
        id              = "shopify-access-token"
        confidence      = "high"
        keyword         = "shpat_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /shpat_[a-fA-F0-9]{32}/  // gitleaks:allow

    condition:
        $secret
}
