// betterleaks v1.10.0's aikido-client-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_AikidoClientSecret
{
    meta:
        description     = "Detected an Aikido client secret, which may allow unauthorized access to Aikido APIs when paired with a client ID."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AikidoClientSecret"
        severity        = "high"
        score           = 80
        id              = "aikido-client-secret"
        confidence      = "high"
        keyword         = "aik_secret_"
        component1      = "aikido-client-id"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(AIK_SECRET_[A-Za-z0-9]{64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
