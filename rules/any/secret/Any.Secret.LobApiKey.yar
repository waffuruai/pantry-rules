// betterleaks v1.10.0's lob-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_LobApiKey
{
    meta:
        description = "Uncovered a Lob API Key, which could lead to unauthorized access to mailing and address verification services."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "LobApiKey"
        severity    = "medium"
        score       = 50
        id          = "lob-api-key"
        confidence  = "medium"
        keyword     = "test_"
        keyword     = "live_"

    strings:
        $secret = /(?:[lL][oO][bB])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(([lL][iI][vV][eE]|[tT][eE][sS][tT])_[A-Fa-f0-9]{35})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
