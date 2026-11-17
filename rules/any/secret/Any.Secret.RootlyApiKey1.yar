// betterleaks v1.10.0's rootly-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_RootlyApiKey1
{
    meta:
        description     = "Rootly API key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "RootlyApiKey1"
        severity        = "high"
        score           = 80
        id              = "rootly-api-key.1"
        confidence      = "high"
        keyword         = "rootly_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(rootly_[a-f0-9]{64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
