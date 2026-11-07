// betterleaks v1.10.0's clickhouse-cloud-api-secret-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ClickhouseCloudApiSecretKey
{
    meta:
        description     = "Identified a pattern that may indicate clickhouse cloud API secret key, risking unauthorized clickhouse cloud api access and data breaches on ClickHouse Cloud platforms."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ClickhouseCloudApiSecretKey"
        severity        = "high"
        score           = 80
        id              = "clickhouse-cloud-api-secret-key"
        confidence      = "high"
        keyword         = "4b1d"
        component1      = "clickhouse-cloud-key-id"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(4b1d[A-Za-z0-9]{38})\b/  // gitleaks:allow

    condition:
        $secret
}
