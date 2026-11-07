// betterleaks v1.10.0's asaas-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_AsaasApiToken
{
    meta:
        description     = "Detected an Asaas API token, which may expose payment and customer data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AsaasApiToken"
        severity        = "high"
        score           = 80
        id              = "asaas-api-token"
        confidence      = "high"
        keyword         = "$aact_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:^|[^A-Za-z0-9_-])(\$aact_(?:prod|hmlg)_[A-Za-z0-9_-]{20,100})(?:[^A-Za-z0-9_-]|$)/  // gitleaks:allow

    condition:
        $secret
}
