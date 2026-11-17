// betterleaks v1.10.0's snyk-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SnykApiToken
{
    meta:
        description = "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "SnykApiToken"
        severity    = "high"
        score       = 80
        id          = "snyk-api-token"
        confidence  = "high"
        keyword     = "snyk"

    strings:
        $secret = /(?:[sS][nN][yY][kK][_.-]?(?:(?:[aA][pP][iI]|[oO][aA][uU][tT][hH])[_.-]?)?(?:[kK][eE][yY]|[tT][oO][kK][eE][nN]))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
