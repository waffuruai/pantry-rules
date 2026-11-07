// betterleaks v1.10.0's langfuse-public-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_LangfusePublicKey1
{
    meta:
        description     = "Langfuse public key, used as a component of the Langfuse secret-key composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "LangfusePublicKey1"
        severity        = "high"
        score           = 80
        id              = "langfuse-public-key.1"
        confidence      = "high"
        keyword         = "pk-lf-"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(pk-lf-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
