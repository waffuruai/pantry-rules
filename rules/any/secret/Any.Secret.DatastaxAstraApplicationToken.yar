// betterleaks v1.10.0's datastax-astra-application-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_DatastaxAstraApplicationToken
{
    meta:
        description     = "DataStax Astra application token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DatastaxAstraApplicationToken"
        severity        = "high"
        score           = 80
        id              = "datastax-astra-application-token"
        confidence      = "high"
        keyword         = "astracs:"
        skip_entropy_lt = "4.0"

    strings:
        $secret = /\b(AstraCS:[A-Za-z0-9]{20,})/  // gitleaks:allow

    condition:
        $secret
}
