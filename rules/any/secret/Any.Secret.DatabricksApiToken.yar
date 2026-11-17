// betterleaks v1.10.0's databricks-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DatabricksApiToken
{
    meta:
        description     = "Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DatabricksApiToken"
        severity        = "high"
        score           = 80
        id              = "databricks-api-token"
        confidence      = "high"
        keyword         = "dapi"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(dapi[a-f0-9]{32}(?:-\d)?)(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
