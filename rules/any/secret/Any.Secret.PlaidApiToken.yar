// betterleaks v1.10.0's plaid-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_PlaidApiToken
{
    meta:
        description = "Discovered a Plaid API Token, potentially compromising financial data aggregation and banking services."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "PlaidApiToken"
        severity    = "high"
        score       = 80
        id          = "plaid-api-token"
        confidence  = "high"
        keyword     = "plaid"

    strings:
        $secret = /(?:[pP][lL][aA][iI][dD])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([aA][cC][cC][eE][sS][sS]-(?:[sS][aA][nN][dD][bB][oO][xX]|[dD][eE][vV][eE][lL][oO][pP][mM][eE][nN][tT]|[pP][rR][oO][dD][uU][cC][tT][iI][oO][nN])-[A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
