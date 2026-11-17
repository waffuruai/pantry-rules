// betterleaks v1.10.0's langchain-langsmith-service-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_LangchainLangsmithServiceKey
{
    meta:
        description     = "LangSmith service API key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "LangchainLangsmithServiceKey"
        severity        = "high"
        score           = 80
        id              = "langchain-langsmith-service-key"
        confidence      = "high"
        keyword         = "lsv2_sk_"
        skip_entropy_lt = "4.0"

    strings:
        $secret = /\b(lsv2_sk_[0-9a-fA-F]{32}_[0-9a-fA-F]{10})/  // gitleaks:allow

    condition:
        $secret
}
