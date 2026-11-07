// betterleaks v1.10.0's scaleway-secret-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ScalewaySecretKey
{
    meta:
        description     = "Identified a standalone Scaleway Secret Key. This can be used to authenticate API requests."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ScalewaySecretKey"
        severity        = "high"
        score           = 80
        id              = "scaleway-secret-key"
        confidence      = "high"
        keyword         = "scaleway"
        keyword         = "scw"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /(?:(?:[sS][cC][aA][lL][eE][wW][aA][yY]|[sS][cC][wW]).{0,20}?(?:[sS][eE][cC][rR][eE][tT]|[tT][oO][kK][eE][nN]))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
