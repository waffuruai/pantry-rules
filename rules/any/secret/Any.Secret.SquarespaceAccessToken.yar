// betterleaks v1.10.0's squarespace-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SquarespaceAccessToken
{
    meta:
        description = "Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "SquarespaceAccessToken"
        severity    = "medium"
        score       = 50
        id          = "squarespace-access-token"
        confidence  = "medium"
        keyword     = "squarespace"

    strings:
        $secret = /(?:[sS][qQ][uU][aA][rR][eE][sS][pP][aA][cC][eE])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
