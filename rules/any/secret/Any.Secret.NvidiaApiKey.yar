// betterleaks v1.10.0's nvidia-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_NvidiaApiKey
{
    meta:
        description     = "Detected an NVIDIA NIM API Key, which may expose AI inference and GPU cloud services to unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "NvidiaApiKey"
        severity        = "high"
        score           = 80
        id              = "nvidia-api-key"
        confidence      = "high"
        keyword         = "nvapi-"
        skip_entropy_le = "3.5"

    strings:
        $secret = /\b([nN][vV][aA][pP][iI]-[a-zA-Z0-9_-]{60,70})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
