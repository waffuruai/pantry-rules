// betterleaks v1.10.0's auth0-domain.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_Auth0Domain1
{
    meta:
        description = "Auth0 tenant domain, used as a component of the Auth0 client-secret composite rule."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "Auth0Domain1"
        severity    = "high"
        score       = 80
        id          = "auth0-domain.1"
        confidence  = "high"
        keyword     = "auth0.com"

    strings:
        $secret = /\b((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[aA][uU][tT][hH]0\.[cC][oO][mM])(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
