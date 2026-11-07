// betterleaks v1.10.0's settlemint-personal-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SettlemintPersonalAccessToken
{
    meta:
        description     = "Found a Settlemint Personal Access Token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SettlemintPersonalAccessToken"
        severity        = "high"
        score           = 80
        id              = "settlemint-personal-access-token"
        confidence      = "high"
        keyword         = "sm_pat"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(sm_pat_[a-zA-Z0-9]{16})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
