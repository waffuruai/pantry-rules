// betterleaks v1.10.0's ebay-client-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_EbayClientSecret
{
    meta:
        description     = "eBay client secret."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "EbayClientSecret"
        severity        = "high"
        score           = 80
        id              = "ebay-client-secret"
        confidence      = "high"
        keyword         = "ebay"
        component1      = "ebay-client-id"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /(?:(?:[eE][bB][aA][yY](?:[_. -]*(?:[cC][lL][iI][eE][nN][tT]|[aA][pP][iI]))?[_. -]*(?:[sS][eE][cC][rR][eE][tT]|[kK][eE][yY]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(PRD-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4,12})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
