// betterleaks v1.10.0's easypost-test-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_EasypostTestApiToken
{
    meta:
        description     = "Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "EasypostTestApiToken"
        severity        = "high"
        score           = 80
        id              = "easypost-test-api-token"
        confidence      = "high"
        keyword         = "eztk"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\bEZTK[A-Za-z0-9]{54}\b/  // gitleaks:allow

    condition:
        $secret
}
