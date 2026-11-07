// betterleaks v1.10.0's gitlab-rrt rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GitlabRrt
{
    meta:
        description     = "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabRrt"
        severity        = "high"
        score           = 80
        id              = "gitlab-rrt"
        confidence      = "high"
        keyword         = "gr1348941"
        skip_entropy_le = "3.0"

    strings:
        $secret = /GR1348941[\w-]{20}/  // gitleaks:allow

    condition:
        $secret
}
