// betterleaks v1.10.0's prefect-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_PrefectApiToken
{
    meta:
        description     = "Detected a Prefect API token, risking unauthorized access to workflow management and automation services."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PrefectApiToken"
        severity        = "high"
        score           = 80
        id              = "prefect-api-token"
        confidence      = "high"
        keyword         = "pnu_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\b(pnu_[a-zA-Z0-9]{36})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
