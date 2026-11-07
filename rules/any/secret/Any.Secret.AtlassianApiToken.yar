// betterleaks v1.10.0's atlassian-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_AtlassianApiToken
{
    meta:
        description         = "Detected an Atlassian Cloud API token, posing a threat to project management and collaboration tool security and data confidentiality."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "AtlassianApiToken"
        severity            = "high"
        score               = 80
        id                  = "atlassian-api-token"
        confidence          = "high"
        keyword             = "atat"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /\b(ATAT[A-Za-z0-9_\-=]{100,})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
