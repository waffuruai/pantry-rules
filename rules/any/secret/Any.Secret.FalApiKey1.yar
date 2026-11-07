// betterleaks v1.10.0's fal-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_FalApiKey1
{
    meta:
        description     = "Fal.ai API key, which may allow access to model execution, billing, and platform APIs."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "FalApiKey1"
        severity        = "high"
        score           = 80
        id              = "fal-api-key.1"
        confidence      = "high"
        keyword         = "falai"
        keyword         = "fal_ai"
        keyword         = "fal-ai"
        keyword         = "fal.ai"
        keyword         = "fal-api"
        keyword         = "fal_api"
        keyword         = "fal_key"
        keyword         = "fal-key"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:(?:[fF][aA][lL][aA][iI]|[fF][aA][lL]_[aA][iI]|[fF][aA][lL]-[aA][iI]|[fF][aA][lL].[aA][iI]|[fF][aA][lL]-[aA][pP][iI]|[fF][aA][lL]_[aA][pP][iI]|[fF][aA][lL]_[kK][eE][yY]|[fF][aA][lL]-[kK][eE][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:[a-f0-9]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
