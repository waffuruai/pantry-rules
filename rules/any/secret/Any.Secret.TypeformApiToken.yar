// betterleaks v1.10.0's typeform-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_TypeformApiToken
{
    meta:
        description = "Uncovered a Typeform API token, which could lead to unauthorized survey management and data collection."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "TypeformApiToken"
        severity    = "high"
        score       = 80
        id          = "typeform-api-token"
        confidence  = "high"
        keyword     = "tfp_"

    strings:
        $secret = /(?:[tT][yY][pP][eE][fF][oO][rR][mM])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([tT][fF][pP]_[A-Za-z0-9\-_\.=]{59})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
