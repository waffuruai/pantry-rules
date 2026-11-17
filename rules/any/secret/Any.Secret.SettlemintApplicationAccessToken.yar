// betterleaks v1.10.0's settlemint-application-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SettlemintApplicationAccessToken
{
    meta:
        description     = "Found a Settlemint Application Access Token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SettlemintApplicationAccessToken"
        severity        = "high"
        score           = 80
        id              = "settlemint-application-access-token"
        confidence      = "high"
        keyword         = "sm_aat"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(sm_aat_[a-zA-Z0-9]{16})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
