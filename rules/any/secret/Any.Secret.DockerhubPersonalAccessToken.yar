// betterleaks v1.10.0's dockerhub-personal-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DockerhubPersonalAccessToken
{
    meta:
        description     = "Detected a Docker Hub personal access token, which may expose Docker Hub account access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DockerhubPersonalAccessToken"
        severity        = "high"
        score           = 80
        id              = "dockerhub-personal-access-token"
        confidence      = "high"
        keyword         = "dckr_pat_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(dckr_pat_[A-Za-z0-9_-]{27})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
