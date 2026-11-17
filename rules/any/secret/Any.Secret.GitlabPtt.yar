// betterleaks v1.10.0's gitlab-ptt rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GitlabPtt
{
    meta:
        description     = "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabPtt"
        severity        = "high"
        score           = 80
        id              = "gitlab-ptt"
        confidence      = "high"
        keyword         = "glptt-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /glptt-[0-9a-f]{40}/  // gitleaks:allow

    condition:
        $secret
}
