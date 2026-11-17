// betterleaks v1.10.0's gitlab-pat-routable rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GitlabPatRoutable
{
    meta:
        description     = "Identified a GitLab Personal Access Token (routable), risking unauthorized access to GitLab repositories and codebase exposure."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabPatRoutable"
        severity        = "high"
        score           = 80
        id              = "gitlab-pat-routable"
        confidence      = "high"
        keyword         = "glpat-"
        skip_entropy_le = "4.0"

    strings:
        $secret = /\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b/  // gitleaks:allow

    condition:
        $secret
}
