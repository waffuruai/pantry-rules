// betterleaks v1.10.0's shippo-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ShippoApiToken
{
    meta:
        description     = "Discovered a Shippo API token, potentially compromising shipping services and customer order data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ShippoApiToken"
        severity        = "high"
        score           = 80
        id              = "shippo-api-token"
        confidence      = "high"
        keyword         = "shippo_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
