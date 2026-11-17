// betterleaks v1.10.0's temporal-cloud-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_TemporalCloudApiKey1
{
    meta:
        description     = "Temporal Cloud API key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "TemporalCloudApiKey1"
        severity        = "high"
        score           = 80
        id              = "temporal-cloud-api-key.1"
        confidence      = "high"
        keyword         = "inrlbxbvcmfslmlv"
        skip_entropy_lt = "3.2"
        require_secret  = "^(?:[^0-9]*[0-9]){3}"  // gitleaks:allow

    strings:
        $secret = /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*Y2NvdW50X2lk[A-Za-z0-9_-]*InRlbXBvcmFsLmlv[A-Za-z0-9_-]*(?:ICJrZXlfaWQiOi|a2V5X2lk|rZXlfaWQi)[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
