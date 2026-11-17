// betterleaks v1.10.0's tableau-server-host.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_TableauServerHost1
{
    meta:
        description = "Tableau Online server host, used as a component of the personal access-token rule."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "TableauServerHost1"
        severity    = "high"
        score       = 80
        id          = "tableau-server-host.1"
        confidence  = "high"
        keyword     = "online.tableau.com"

    strings:
        $secret = /\b([A-Za-z0-9-]+\.[oO][nN][lL][iI][nN][eE]\.[tT][aA][bB][lL][eE][aA][uU]\.[cC][oO][mM])\b/  // gitleaks:allow

    condition:
        $secret
}
