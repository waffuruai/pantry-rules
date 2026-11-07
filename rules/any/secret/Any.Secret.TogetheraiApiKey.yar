// betterleaks v1.10.0's togetherai-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_TogetheraiApiKey
{
    meta:
        description     = "Detected a Together.ai API Key, which may expose access to open-source AI models and inference services."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "TogetheraiApiKey"
        severity        = "high"
        score           = 80
        id              = "togetherai-api-key"
        confidence      = "high"
        keyword         = "tgp_v1_"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b([tT][gG][pP]_[vV]1_[a-zA-ZA-Za-z0-9_-]{43})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
