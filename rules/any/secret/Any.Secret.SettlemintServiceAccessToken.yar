// betterleaks v1.10.0's settlemint-service-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SettlemintServiceAccessToken
{
    meta:
        description     = "Found a Settlemint Service Access Token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SettlemintServiceAccessToken"
        severity        = "high"
        score           = 80
        id              = "settlemint-service-access-token"
        confidence      = "high"
        keyword         = "sm_sat"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(sm_sat_[a-zA-Z0-9]{16})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
