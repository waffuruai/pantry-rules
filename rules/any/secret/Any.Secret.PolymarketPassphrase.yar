// betterleaks v1.10.0's polymarket-passphrase rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_PolymarketPassphrase
{
    meta:
        description = "Found a Polymarket API passphrase, used as a component of authenticated Polymarket API requests."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "PolymarketPassphrase"
        severity    = "medium"
        score       = 50
        id          = "polymarket-passphrase"
        confidence  = "medium"
        keyword     = "poly"

    strings:
        $secret = /(?:(?:[pP][oO][lL][yY].{0,20}[pP][aA][sS][sS][pP][hH][rR][aA][sS][eE])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9_]{8,128})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
