// betterleaks v1.10.0's beamer-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_BeamerApiToken
{
    meta:
        description = "Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "BeamerApiToken"
        severity    = "medium"
        score       = 50
        id          = "beamer-api-token"
        confidence  = "medium"
        keyword     = "beamer"

    strings:
        $secret = /(?:[bB][eE][aA][mM][eE][rR])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([bB]_[A-Za-z0-9=_\-]{44})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
