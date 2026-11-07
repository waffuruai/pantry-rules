// betterleaks v1.10.0's pinecone-api-key.2 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PineconeApiKey2
{
    meta:
        description     = "Pinecone API key version 2 (pcsk format)."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PineconeApiKey2"
        severity        = "high"
        score           = 80
        id              = "pinecone-api-key.2"
        confidence      = "high"
        keyword         = "pcsk_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(pcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
