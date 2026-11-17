// betterleaks v1.10.0's shopify-custom-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ShopifyCustomAccessToken
{
    meta:
        description     = "Detected a Shopify custom access token, potentially compromising custom app integrations and e-commerce data security."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ShopifyCustomAccessToken"
        severity        = "high"
        score           = 80
        id              = "shopify-custom-access-token"
        confidence      = "high"
        keyword         = "shpca_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /shpca_[a-fA-F0-9]{32}/  // gitleaks:allow

    condition:
        $secret
}
