// betterleaks v1.10.0's deepseek-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_DeepseekApiKey
{
    meta:
        description     = "Detected a DeepSeek API Key, which may expose AI model access and associated usage to unauthorized parties."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DeepseekApiKey"
        severity        = "high"
        score           = 80
        id              = "deepseek-api-key"
        confidence      = "high"
        keyword         = "deepseek"
        skip_entropy_le = "3.5"

    strings:
        $secret = /(?:[dD][eE][eE][pP][sS][eE][eE][kK])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([sS][kK]-[A-Fa-f0-9]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
