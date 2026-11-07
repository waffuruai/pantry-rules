// betterleaks v1.10.0's huggingface-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_HuggingfaceAccessToken
{
    meta:
        description     = "Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "HuggingfaceAccessToken"
        severity        = "high"
        score           = 80
        id              = "huggingface-access-token"
        confidence      = "high"
        keyword         = "hf_"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\b(hf_(?:[A-Za-z]{34}))(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
