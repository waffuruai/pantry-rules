// betterleaks v1.10.0's tableau-personal-access-token-name.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_TableauPersonalAccessTokenName1
{
    meta:
        description = "Tableau personal access-token name, used as a component of the token rule."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "TableauPersonalAccessTokenName1"
        severity    = "high"
        score       = 80
        id          = "tableau-personal-access-token-name.1"
        confidence  = "high"
        keyword     = "tableau"

    strings:
        $secret = /(?:(?:[tT][aA][bB][lL][eE][aA][uU](?:[_. -]*(?:[pP][eE][rR][sS][oO][nN][aA][lL][_. -]*[aA][cC][cC][eE][sS][sS]|[pP][aA][tT]))?[_. -]*(?:[tT][oO][kK][eE][nN][_. -]*)?[nN][aA][mM][eE])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z][A-Za-z0-9_-]{2,50})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
