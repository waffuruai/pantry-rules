// betterleaks v1.10.0's gitlab-pat rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GitlabPat
{
    meta:
        description     = "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabPat"
        severity        = "high"
        score           = 80
        id              = "gitlab-pat"
        confidence      = "high"
        keyword         = "glpat-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /glpat-[\w-]{20}/  // gitleaks:allow

    condition:
        $secret
}
