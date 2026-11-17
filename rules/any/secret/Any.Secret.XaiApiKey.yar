// betterleaks v1.10.0's xai-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_XaiApiKey
{
    meta:
        description     = "Detected an xAI (Grok) API Key, which may expose Grok AI model access to unauthorized parties."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "XaiApiKey"
        severity        = "high"
        score           = 80
        id              = "xai-api-key"
        confidence      = "high"
        keyword         = "xai-"
        skip_entropy_le = "3.5"

    strings:
        $secret = /\b([xX][aA][iI]-[a-zA-ZA-Za-z0-9_-]{70,120})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
