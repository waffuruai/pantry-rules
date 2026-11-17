// betterleaks v1.10.0's salesforce-instance-url.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_SalesforceInstanceUrl1
{
    meta:
        description = "Salesforce instance host, used as a component of the Salesforce access-token rule."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "SalesforceInstanceUrl1"
        severity    = "high"
        score       = 80
        id          = "salesforce-instance-url.1"
        confidence  = "high"
        keyword     = "salesforce.com"

    strings:
        $secret = /(?:^|[^A-Za-z0-9.-])(?:[hH][tT][tT][pP][sS]?:\/\/)?((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){0,4}\.[mM][yY]\.[sS][aA][lL][eE][sS][fF][oO][rR][cC][eE]\.[cC][oO][mM]|[A-Za-z]{2,8}[0-9]{1,4}\.[sS][aA][lL][eE][sS][fF][oO][rR][cC][eE]\.[cC][oO][mM]))(?:[^A-Za-z0-9.-]|$)/  // gitleaks:allow

    condition:
        $secret
}
