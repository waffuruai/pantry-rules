// betterleaks v1.10.0's vultr-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_VultrApiKey1
{
    meta:
        description     = "Vultr API key, which may allow management of cloud account resources."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "VultrApiKey1"
        severity        = "medium"
        score           = 50
        id              = "vultr-api-key.1"
        confidence      = "medium"
        keyword         = "vultr"
        skip_entropy_lt = "3.4"

    strings:
        $secret = /(?:[vV][uU][lL][tT][rR])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{36})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
