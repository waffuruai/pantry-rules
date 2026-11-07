// betterleaks v1.10.0's lob-pub-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_LobPubApiKey
{
    meta:
        description = "Detected a Lob Publishable API Key, posing a risk of exposing mail and print service integrations."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "LobPubApiKey"
        severity    = "medium"
        score       = 50
        id          = "lob-pub-api-key"
        confidence  = "medium"
        keyword     = "test_pub_"
        keyword     = "live_pub_"

    strings:
        $secret = /(?:[lL][oO][bB])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(([tT][eE][sS][tT]|[lL][iI][vV][eE])_[pP][uU][bB]_[A-Fa-f0-9]{31})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
