// betterleaks v1.10.0's mergify-application-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_MergifyApplicationKey
{
    meta:
        description     = "Mergify application API key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "MergifyApplicationKey"
        severity        = "high"
        score           = 80
        id              = "mergify-application-key"
        confidence      = "high"
        keyword         = "mergify_application_key_"
        skip_entropy_lt = "3.2"

    strings:
        $secret = /\b(mergify_application_key_[A-Za-z0-9_-]{40,200})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
