// betterleaks v1.10.0's grafana-cloud-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GrafanaCloudApiToken
{
    meta:
        description     = "Found a Grafana cloud API token, risking unauthorized access to cloud-based monitoring services and data exposure."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GrafanaCloudApiToken"
        severity        = "high"
        score           = 80
        id              = "grafana-cloud-api-token"
        confidence      = "high"
        keyword         = "glc_"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(glc_[A-Za-z0-9+\/]{40,150}={0,2})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
