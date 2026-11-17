// betterleaks v1.10.0's mapbox-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_MapboxApiToken
{
    meta:
        description = "Detected a MapBox API token, posing a risk to geospatial services and sensitive location data exposure."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "MapboxApiToken"
        severity    = "high"
        score       = 80
        id          = "mapbox-api-token"
        confidence  = "high"
        keyword     = "mapbox"

    strings:
        $secret = /(?:[mM][aA][pP][bB][oO][xX])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([pP][kK]\.[A-Za-z0-9]{60}\.[A-Za-z0-9]{22})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
