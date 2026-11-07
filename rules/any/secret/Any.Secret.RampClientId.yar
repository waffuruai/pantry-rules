// betterleaks v1.10.0's ramp-client-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_RampClientId
{
    meta:
        description     = "Ramp client ID, used as a component of the Ramp client-secret composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "RampClientId"
        severity        = "high"
        score           = 80
        id              = "ramp-client-id"
        confidence      = "high"
        keyword         = "ramp_id_"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(ramp_id_[A-Za-z0-9]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
