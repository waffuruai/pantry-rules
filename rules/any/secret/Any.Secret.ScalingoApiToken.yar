// betterleaks v1.10.0's scalingo-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ScalingoApiToken
{
    meta:
        description     = "Found a Scalingo API token, posing a risk to cloud platform services and application deployment security."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ScalingoApiToken"
        severity        = "high"
        score           = 80
        id              = "scalingo-api-token"
        confidence      = "high"
        keyword         = "tk-us-"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\b(tk-us-[\w-]{48})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
