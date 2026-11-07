// betterleaks v1.10.0's ebay-client-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_EbayClientId
{
    meta:
        description     = "eBay client ID, used as a component of the eBay client-secret composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "EbayClientId"
        severity        = "high"
        score           = 80
        id              = "ebay-client-id"
        confidence      = "high"
        keyword         = "-prd-"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b([a-zA-Z0-9_-]+-[a-zA-Z0-9_-]+-PRD-[a-f0-9]{8,12}-[a-f0-9]{8,12})/  // gitleaks:allow

    condition:
        $secret
}
