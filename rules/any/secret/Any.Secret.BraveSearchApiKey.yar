// betterleaks v1.10.0's brave-search-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_BraveSearchApiKey
{
    meta:
        description     = "Detected a Brave Search API key, which may allow unauthorized use of Brave Search API quota."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "BraveSearchApiKey"
        severity        = "high"
        score           = 80
        id              = "brave-search-api-key"
        confidence      = "high"
        keyword         = "bsa"
        skip_entropy_lt = "3.2"

    strings:
        $secret = /\b(BSA[A-Za-z0-9_-]{24,40})\b/  // gitleaks:allow

    condition:
        $secret
}
