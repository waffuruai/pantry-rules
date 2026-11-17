// betterleaks v1.10.0's grafana-service-account-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_GrafanaServiceAccountToken
{
    meta:
        description     = "Discovered a Grafana service account token, posing a risk of compromised monitoring services and data integrity."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GrafanaServiceAccountToken"
        severity        = "high"
        score           = 80
        id              = "grafana-service-account-token"
        confidence      = "high"
        keyword         = "glsa_"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
