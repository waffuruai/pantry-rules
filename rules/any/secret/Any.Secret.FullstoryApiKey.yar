// betterleaks v1.10.0's fullstory-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_FullstoryApiKey
{
    meta:
        description     = "FullStory API key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "FullstoryApiKey"
        severity        = "medium"
        score           = 50
        id              = "fullstory-api-key"
        confidence      = "medium"
        keyword         = "fullstory"
        keyword         = "fs_api"
        skip_entropy_lt = "3.3"

    strings:
        $secret = /(?:(?:[fF][uU][lL][lL][sS][tT][oO][rR][yY]|[fF][sS]_[aA][pP][iI]|[fF][uU][lL][lL][sS][tT][oO][rR][yY]_[aA][pP][iI]))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((?:[nN][aA]1|[eE][uU]1)\.[a-zA-ZA-Za-z0-9]{20,})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
