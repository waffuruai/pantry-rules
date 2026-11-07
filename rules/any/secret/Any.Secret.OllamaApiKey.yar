// betterleaks v1.10.0's ollama-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_OllamaApiKey
{
    meta:
        description     = "Detected an Ollama API Key, which may expose local and hosted AI model serving to unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "OllamaApiKey"
        severity        = "high"
        score           = 80
        id              = "ollama-api-key"
        confidence      = "high"
        keyword         = "ollama"
        skip_entropy_le = "3.5"

    strings:
        $secret = /(?:[oO][lL][lL][aA][mM][aA])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{32}\.[A-Za-za-zA-Z0-9_-]{24})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
