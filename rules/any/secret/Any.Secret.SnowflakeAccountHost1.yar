// betterleaks v1.10.0's snowflake-account-host.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_SnowflakeAccountHost1
{
    meta:
        description = "Snowflake account host, used as a component of the programmatic access-token rule."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "SnowflakeAccountHost1"
        severity    = "high"
        score       = 80
        id          = "snowflake-account-host.1"
        confidence  = "high"
        keyword     = "snowflakecomputing.com"

    strings:
        $secret = /\b([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.[sS][nN][oO][wW][fF][lL][aA][kK][eE][cC][oO][mM][pP][uU][tT][iI][nN][gG]\.[cC][oO][mM])\b/  // gitleaks:allow

    condition:
        $secret
}
