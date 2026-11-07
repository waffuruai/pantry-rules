// betterleaks v1.10.0's retell-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_RetellApiKey1
{
    meta:
        description     = "Retell AI API key, which may allow access to agents, calls, and account configuration."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "RetellApiKey1"
        severity        = "high"
        score           = 80
        id              = "retell-api-key.1"
        confidence      = "high"
        keyword         = "retell"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /(?:(?:[rR][eE][tT][eE][lL][lL])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(key_[a-f0-9]{28})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
