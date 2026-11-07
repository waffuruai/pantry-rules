// betterleaks v1.10.0's onesignal-rich-authentication-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_OnesignalRichAuthenticationToken
{
    meta:
        description     = "OneSignal rich authentication token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "OnesignalRichAuthenticationToken"
        severity        = "high"
        score           = 80
        id              = "onesignal-rich-authentication-token"
        confidence      = "high"
        keyword         = "os_v2_app_"
        keyword         = "os_v2_org_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(os_v2_(?:app|org)_[a-z2-7]{103})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
