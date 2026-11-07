// betterleaks v1.10.0's polymarket-api-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_PolymarketApiSecret
{
    meta:
        description     = "Discovered a Polymarket API secret, which could be used to sign authenticated requests to the Polymarket L2 API."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PolymarketApiSecret"
        severity        = "medium"
        score           = 50
        id              = "polymarket-api-secret"
        confidence      = "medium"
        keyword         = "poly"
        skip_entropy_le = "3.0"

    strings:
        $secret = /(?:(?:[pP][oO][lL][yY].{0,20}[sS][eE][cC][rR][eE][tT])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9+\/]{40,}={0,2})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
