// betterleaks v1.10.0's polymarket-address rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_PolymarketAddress
{
    meta:
        description = "Found a Polymarket wallet address, used as a component of authenticated Polymarket API requests."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "PolymarketAddress"
        severity    = "medium"
        score       = 50
        id          = "polymarket-address"
        confidence  = "medium"
        keyword     = "poly"

    strings:
        $secret = /(?:(?:[pP][oO][lL][yY].{0,20}[aA][dD][dD][rR][eE][sS][sS])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(0x[a-fA-F0-9]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
