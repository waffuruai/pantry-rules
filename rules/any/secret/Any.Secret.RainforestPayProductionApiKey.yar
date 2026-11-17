// betterleaks v1.10.0's rainforest-pay-production-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_RainforestPayProductionApiKey
{
    meta:
        description     = "Rainforest Pay production API key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "RainforestPayProductionApiKey"
        severity        = "medium"
        score           = 50
        id              = "rainforest-pay-production-api-key"
        confidence      = "medium"
        keyword         = "rainforest"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:(?:[rR][aA][iI][nN][fF][oO][rR][eE][sS][tT](?:[_. -]*[pP][aA][yY])?(?:[_. -]*(?:[aA][pP][iI]))?[_. -]*(?:[sS][eE][cC][rR][eE][tT]|[kK][eE][yY]|[tT][oO][kK][eE][nN]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(apikey_[a-f0-9]{64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
