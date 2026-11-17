// betterleaks v1.10.0's stability-ai-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_StabilityAiApiKey
{
    meta:
        description     = "Detected a Stability AI API Key, which may expose AI image generation services to unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "StabilityAiApiKey"
        severity        = "medium"
        score           = 50
        id              = "stability-ai-api-key"
        confidence      = "medium"
        keyword         = "stability"
        skip_entropy_le = "3.5"

    strings:
        $secret = /(?:[sS][tT][aA][bB][iI][lL][iI][tT][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([sS][kK]-[a-zA-ZA-Za-z0-9]{48})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
