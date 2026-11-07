// betterleaks v1.10.0's hubspot-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_HubspotApiKey
{
    meta:
        description = "Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "HubspotApiKey"
        severity    = "high"
        score       = 80
        id          = "hubspot-api-key"
        confidence  = "high"
        keyword     = "hubspot"

    strings:
        $secret = /(?:[hH][uU][bB][sS][pP][oO][tT])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9A-F]{8}-[a-f0-9A-F]{4}-[a-f0-9A-F]{4}-[a-f0-9A-F]{4}-[a-f0-9A-F]{12})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
