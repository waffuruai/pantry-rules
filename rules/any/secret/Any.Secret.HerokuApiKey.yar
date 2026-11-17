// betterleaks v1.10.0's heroku-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_HerokuApiKey
{
    meta:
        description = "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "HerokuApiKey"
        severity    = "high"
        score       = 80
        id          = "heroku-api-key"
        confidence  = "high"
        keyword     = "heroku"

    strings:
        $secret = /(?:[hH][eE][rR][oO][kK][uU])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
