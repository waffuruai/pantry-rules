// betterleaks v1.10.0's mercury-production-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_MercuryProductionApiToken
{
    meta:
        description     = "Mercury production API token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "MercuryProductionApiToken"
        severity        = "high"
        score           = 80
        id              = "mercury-production-api-token"
        confidence      = "high"
        keyword         = "mercury_production_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(mercury_production_[a-z]{3,6}_[A-Za-z0-9]{40,50}_yrucrem)(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
