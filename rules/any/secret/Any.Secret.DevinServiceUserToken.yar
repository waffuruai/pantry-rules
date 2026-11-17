// betterleaks v1.10.0's devin-service-user-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_DevinServiceUserToken
{
    meta:
        description     = "Detected a Cognition Devin service user token, which may expose Devin service user access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DevinServiceUserToken"
        severity        = "high"
        score           = 80
        id              = "devin-service-user-token"
        confidence      = "high"
        keyword         = "cog_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(cog_[a-z2-7]{52})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
