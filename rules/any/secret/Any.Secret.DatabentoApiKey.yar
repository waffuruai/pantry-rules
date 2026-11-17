// betterleaks v1.10.0's databento-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_DatabentoApiKey
{
    meta:
        description = "Databento API key."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "DatabentoApiKey"
        severity    = "high"
        score       = 80
        id          = "databento-api-key"
        confidence  = "high"
        keyword     = "databento"

    strings:
        $secret = /(?:[dD][aA][tT][aA][bB][eE][nN][tT][oO])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([dD][bB]-[a-zA-ZA-Za-z0-9]{29})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
