// betterleaks v1.10.0's clickhouse-cloud-key-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_ClickhouseCloudKeyId
{
    meta:
        description     = "Detected a ClickHouse Cloud key ID, used as a component of the clickhouse-cloud-api-secret-key composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ClickhouseCloudKeyId"
        severity        = "high"
        score           = 80
        id              = "clickhouse-cloud-key-id"
        confidence      = "high"
        keyword         = "clickhouse"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b[cC][lL][iI][cC][kK][hH][oO][uU][sS][eE](?:.|[\n\r]){0,16}?(?:[Ii][Dd]|[Uu][Ss][Ee][Rr])(?:.|[\n\r]){0,16}?([A-Za-z0-9]{20})/  // gitleaks:allow

    condition:
        $secret
}
