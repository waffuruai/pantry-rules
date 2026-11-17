// betterleaks v1.10.0's mem0-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_Mem0ApiKey1
{
    meta:
        description     = "Mem0 API key, which may allow access to stored application memories."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "Mem0ApiKey1"
        severity        = "high"
        score           = 80
        id              = "mem0-api-key.1"
        confidence      = "high"
        keyword         = "mem0"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /(?:(?:[mM][eE][mM]0)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(m0-[A-Za-z0-9]{24,44})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
