// betterleaks v1.10.0's dynatrace-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DynatraceApiToken
{
    meta:
        description     = "Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DynatraceApiToken"
        severity        = "high"
        score           = 80
        id              = "dynatrace-api-token"
        confidence      = "high"
        keyword         = "dt0c01."
        skip_entropy_le = "4.0"

    strings:
        $secret = /dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}/  // gitleaks:allow

    condition:
        $secret
}
