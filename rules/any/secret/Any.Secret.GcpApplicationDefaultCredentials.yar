// betterleaks v1.10.0's gcp-application-default-credentials rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GcpApplicationDefaultCredentials
{
    meta:
        description = "Google (GCP) Application Default Credentials"
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "GcpApplicationDefaultCredentials"
        severity    = "high"
        score       = 80
        id          = "gcp-application-default-credentials"
        confidence  = "high"
        keyword     = ".apps.googleusercontent.com"

    strings:
        $secret = /\{[^\{]+(?:(?:"client_secret"\s*:\s*"[^"]+"[^\}]+"refresh_token"\s*:\s*"[^"]+")|(?:"refresh_token"\s*:\s*"[^"]+"[^\}]+"client_secret"\s*:\s*"[^"]+"))[^\}]+\}/  // gitleaks:allow

    condition:
        $secret
}
