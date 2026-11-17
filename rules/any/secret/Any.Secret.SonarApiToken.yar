// betterleaks v1.10.0's sonar-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SonarApiToken
{
    meta:
        description  = "Uncovered a Sonar API token, potentially compromising software vulnerability scanning and code security."
        author       = "betterleaks"
        reference    = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license      = "MIT"
        os           = "any"
        category     = "secret"
        family       = "SonarApiToken"
        severity     = "high"
        score        = 80
        id           = "sonar-api-token"
        confidence   = "high"
        keyword      = "sonar"
        secret_group = 2

    strings:
        $secret = /(?:[sS][oO][nN][aA][rR][_.-]?([lL][oO][gG][iI][nN]|[tT][oO][kK][eE][nN]))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((?:[sS][qQ][uU]_|[sS][qQ][pP]_|[sS][qQ][aA]_)?[A-Za-z0-9=_\-]{40})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
