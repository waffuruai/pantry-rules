// betterleaks v1.10.0's ramp-client-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_RampClientSecret
{
    meta:
        description     = "Ramp OAuth client secret."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "RampClientSecret"
        severity        = "high"
        score           = 80
        id              = "ramp-client-secret"
        confidence      = "high"
        keyword         = "ramp_sec_"
        component1      = "ramp-client-id"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(ramp_sec_[A-Za-z0-9]{48})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
