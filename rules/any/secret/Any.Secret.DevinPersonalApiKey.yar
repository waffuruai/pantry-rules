// betterleaks v1.10.0's devin-personal-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_DevinPersonalApiKey
{
    meta:
        description     = "Detected a Cognition Devin personal API key, which may expose Devin sessions and user data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DevinPersonalApiKey"
        severity        = "high"
        score           = 80
        id              = "devin-personal-api-key"
        confidence      = "high"
        keyword         = "apk_user_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(apk_user_[A-Za-z0-9+\/]{120,180}={0,2})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
