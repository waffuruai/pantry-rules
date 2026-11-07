// betterleaks v1.10.0's duffel-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DuffelApiToken
{
    meta:
        description     = "Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DuffelApiToken"
        severity        = "high"
        score           = 80
        id              = "duffel-api-token"
        confidence      = "high"
        keyword         = "duffel_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /duffel_(?:test|live)_[A-Za-z0-9_\-=]{43}/  // gitleaks:allow

    condition:
        $secret
}
