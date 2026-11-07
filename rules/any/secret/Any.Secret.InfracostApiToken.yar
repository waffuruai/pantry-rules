// betterleaks v1.10.0's infracost-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_InfracostApiToken
{
    meta:
        description     = "Detected an Infracost API Token, risking unauthorized access to cloud cost estimation tools and financial data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "InfracostApiToken"
        severity        = "high"
        score           = 80
        id              = "infracost-api-token"
        confidence      = "high"
        keyword         = "ico-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(ico-[a-zA-Z0-9]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
