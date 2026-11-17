// betterleaks v1.10.0's polymarket-private-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_PolymarketPrivateKey
{
    meta:
        description     = "Discovered a Polymarket private key, which could allow unauthorized trading and fund transfers."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PolymarketPrivateKey"
        severity        = "medium"
        score           = 50
        id              = "polymarket-private-key"
        confidence      = "medium"
        keyword         = "poly"
        skip_entropy_le = "3.5"

    strings:
        $secret = /(?:(?:[pP][oO][lL][yY].{0,20}[pP][rR][iI][vV][aA][tT][eE].{0,20}[kK][eE][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(0x[a-fA-F0-9]{64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
