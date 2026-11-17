// betterleaks v1.10.0's cockroachlabs-cloud-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_CockroachlabsCloudApiKey
{
    meta:
        description     = "Detected a CockroachDB Cloud service account API key, which may allow unauthorized access to CockroachDB Cloud resources."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "CockroachlabsCloudApiKey"
        severity        = "high"
        score           = 80
        id              = "cockroachlabs-cloud-api-key"
        confidence      = "high"
        keyword         = "ccdb1_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(CCDB1_[A-Za-z0-9]{22}_[A-Za-z0-9]{40})\b/  // gitleaks:allow

    condition:
        $secret
}
