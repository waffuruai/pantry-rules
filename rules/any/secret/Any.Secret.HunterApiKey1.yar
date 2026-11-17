// betterleaks v1.10.0's hunter-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_HunterApiKey1
{
    meta:
        description     = "Hunter API key, which may allow access to account and email intelligence data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "HunterApiKey1"
        severity        = "medium"
        score           = 50
        id              = "hunter-api-key.1"
        confidence      = "medium"
        keyword         = "hunter"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:(?:[hH][uU][nN][tT][eE][rR])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
