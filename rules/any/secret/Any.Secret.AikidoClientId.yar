// betterleaks v1.10.0's aikido-client-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_AikidoClientId
{
    meta:
        description     = "Detected an Aikido client ID, used as a component of the aikido-client-secret composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AikidoClientId"
        severity        = "high"
        score           = 80
        id              = "aikido-client-id"
        confidence      = "high"
        keyword         = "aik_client_"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(AIK_CLIENT_[A-Za-z0-9]{24})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
