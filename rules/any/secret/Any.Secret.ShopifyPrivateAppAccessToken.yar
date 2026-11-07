// betterleaks v1.10.0's shopify-private-app-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ShopifyPrivateAppAccessToken
{
    meta:
        description     = "Identified a Shopify private app access token, risking unauthorized access to private app data and store operations."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ShopifyPrivateAppAccessToken"
        severity        = "high"
        score           = 80
        id              = "shopify-private-app-access-token"
        confidence      = "high"
        keyword         = "shppa_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /shppa_[a-fA-F0-9]{32}/  // gitleaks:allow

    condition:
        $secret
}
