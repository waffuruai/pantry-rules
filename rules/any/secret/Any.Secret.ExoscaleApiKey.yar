// betterleaks v1.10.0's exoscale-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ExoscaleApiKey
{
    meta:
        description       = "Identified an Exoscale API key paired with a secret, which together grant programmatic access to Exoscale cloud resources."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "ExoscaleApiKey"
        severity          = "high"
        score             = 80
        id                = "exoscale-api-key"
        confidence        = "high"
        keyword           = "exo"
        component1        = "exoscale-api-secret"
        component1_within = "5L"
        skip_entropy_lt   = "3.0"

    strings:
        $secret = /\b(EXO[a-zA-Z0-9]{24,30})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
