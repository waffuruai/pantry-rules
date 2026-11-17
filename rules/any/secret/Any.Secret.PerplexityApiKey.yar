// betterleaks v1.10.0's perplexity-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PerplexityApiKey
{
    meta:
        description     = "Detected a Perplexity API key, which could lead to unauthorized access to Perplexity AI services and data exposure."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PerplexityApiKey"
        severity        = "high"
        score           = 80
        id              = "perplexity-api-key"
        confidence      = "high"
        keyword         = "pplx-"
        skip_entropy_le = "4.0"

    strings:
        $secret = /\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)/  // gitleaks:allow

    condition:
        $secret
}
