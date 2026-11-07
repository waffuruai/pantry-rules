// betterleaks v1.10.0's heroku-api-key-v2 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_HerokuApiKeyV2
{
    meta:
        description     = "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "HerokuApiKeyV2"
        severity        = "high"
        score           = 80
        id              = "heroku-api-key-v2"
        confidence      = "high"
        keyword         = "hrku-aa"
        skip_entropy_le = "4.0"

    strings:
        $secret = /\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
