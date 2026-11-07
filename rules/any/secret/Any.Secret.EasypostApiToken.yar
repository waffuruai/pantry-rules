// betterleaks v1.10.0's easypost-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_EasypostApiToken
{
    meta:
        description     = "Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "EasypostApiToken"
        severity        = "high"
        score           = 80
        id              = "easypost-api-token"
        confidence      = "high"
        keyword         = "ezak"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\bEZAK[A-Za-z0-9]{54}\b/  // gitleaks:allow

    condition:
        $secret
}
