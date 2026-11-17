// betterleaks v1.10.0's midtrans-production-server-client-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_MidtransProductionServerClientKey
{
    meta:
        description     = "Midtrans production server or client key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "MidtransProductionServerClientKey"
        severity        = "high"
        score           = 80
        id              = "midtrans-production-server-client-key"
        confidence      = "high"
        keyword         = "mid-server-"
        keyword         = "mid-client-"
        skip_entropy_lt = "2.8"

    strings:
        $secret = /(?:[mM][iI][dD][tT][rR][aA][nN][sS]|[mM][iI][dD][_-]?)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([Mm][iI][dD]-(?:[sS][eE][rR][vV][eE][rR]|[cC][lL][iI][eE][nN][tT])-[a-zA-ZA-Za-z0-9_]{10,20})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
