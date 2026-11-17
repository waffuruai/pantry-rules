// betterleaks v1.10.0's langfuse-secret-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_LangfuseSecretKey1
{
    meta:
        description       = "Langfuse secret key, which authenticates project API access when paired with its public key."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "LangfuseSecretKey1"
        severity          = "high"
        score             = 80
        id                = "langfuse-secret-key.1"
        confidence        = "high"
        keyword           = "sk-lf-"
        component1        = "langfuse-public-key.1"
        component1_within = "5L"
        skip_entropy_lt   = "3.0"

    strings:
        $secret = /\b(sk-lf-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
