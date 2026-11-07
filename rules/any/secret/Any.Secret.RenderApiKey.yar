// betterleaks v1.10.0's render-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_RenderApiKey
{
    meta:
        description     = "Detected a Render API key, which may expose hosted services and account resources to unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "RenderApiKey"
        severity        = "high"
        score           = 80
        id              = "render-api-key"
        confidence      = "high"
        keyword         = "rnd_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(rnd_[A-Za-z0-9]{28})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
