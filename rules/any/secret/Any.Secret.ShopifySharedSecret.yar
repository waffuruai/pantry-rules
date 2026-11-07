// betterleaks v1.10.0's shopify-shared-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ShopifySharedSecret
{
    meta:
        description     = "Found a Shopify shared secret, posing a risk to application authentication and e-commerce platform security."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ShopifySharedSecret"
        severity        = "high"
        score           = 80
        id              = "shopify-shared-secret"
        confidence      = "high"
        keyword         = "shpss_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /shpss_[a-fA-F0-9]{32}/  // gitleaks:allow

    condition:
        $secret
}
