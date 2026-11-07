// betterleaks v1.10.0's voyageai-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_VoyageaiApiKey
{
    meta:
        description     = "Detected a Voyage AI API key, which may expose embedding and retrieval model access to unauthorized parties."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "VoyageaiApiKey"
        severity        = "medium"
        score           = 50
        id              = "voyageai-api-key"
        confidence      = "medium"
        keyword         = "voyage"
        skip_entropy_lt = "4.0"

    strings:
        $secret = /(?:(?:[vV][oO][yY][aA][gG][eE])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((?:pa|al)-[A-Za-z0-9_-]{43})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
