// betterleaks v1.10.0's azure-ad-client-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AzureAdClientSecret
{
    meta:
        description       = "Azure AD Client Secret"
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "AzureAdClientSecret"
        severity          = "high"
        score             = 80
        id                = "azure-ad-client-secret"
        confidence        = "high"
        keyword           = "0q~"
        keyword           = "1q~"
        keyword           = "2q~"
        keyword           = "3q~"
        keyword           = "4q~"
        keyword           = "5q~"
        keyword           = "6q~"
        keyword           = "7q~"
        keyword           = "8q~"
        keyword           = "9q~"
        component1        = "azure-tenant-id"
        component1_within = "8L"
        component2        = "azure-client-id"
        component2_within = "8L"
        skip_entropy_le   = "3.0"

    strings:
        $secret = /(?:^|[\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"\x60\s<),])/  // gitleaks:allow

    condition:
        $secret
}
