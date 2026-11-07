// betterleaks v1.10.0's llama-cloud-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_LlamaCloudApiKey1
{
    meta:
        description     = "LlamaCloud API key, which may allow access to managed parsing, ingestion, and retrieval projects."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "LlamaCloudApiKey1"
        severity        = "high"
        score           = 80
        id              = "llama-cloud-api-key.1"
        confidence      = "high"
        keyword         = "llx-"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(llx-[A-Za-z0-9]{44,52})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
