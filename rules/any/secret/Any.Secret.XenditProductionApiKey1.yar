// betterleaks v1.10.0's xendit-production-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_XenditProductionApiKey1
{
    meta:
        description     = "Xendit production API key, which may allow access to payment and balance APIs."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "XenditProductionApiKey1"
        severity        = "high"
        score           = 80
        id              = "xendit-production-api-key.1"
        confidence      = "high"
        keyword         = "xnd_production_"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(xnd_production_[A-Za-z0-9]{56,72})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
