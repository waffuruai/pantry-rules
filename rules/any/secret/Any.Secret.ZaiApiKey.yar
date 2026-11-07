// betterleaks v1.10.0's zai-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ZaiApiKey
{
    meta:
        description     = "Detected a Z.ai API key, which may expose GLM model access and usage to unauthorized parties."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ZaiApiKey"
        severity        = "medium"
        score           = 50
        id              = "zai-api-key"
        confidence      = "medium"
        keyword         = "zai"
        keyword         = "z_ai"
        keyword         = "z.ai"
        keyword         = "glm"
        keyword         = "zlm"
        skip_entropy_le = "3.5"

    strings:
        $secret = /(?:[zZ][aA][iI]|[zZ]_[aA][iI]|[zZ]\.[aA][iI]|[gG][lL][mM]|[zZ][lL][mM])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{32}\.[A-Za-z0-9]{16})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
