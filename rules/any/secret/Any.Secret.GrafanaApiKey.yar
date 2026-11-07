// betterleaks v1.10.0's grafana-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_GrafanaApiKey
{
    meta:
        description     = "Identified a Grafana API key, which could compromise monitoring dashboards and sensitive data analytics."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GrafanaApiKey"
        severity        = "high"
        score           = 80
        id              = "grafana-api-key"
        confidence      = "high"
        keyword         = "eyjrijoi"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(eyJrIjoi[A-Za-z0-9+\/]{40,380}={0,2})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
