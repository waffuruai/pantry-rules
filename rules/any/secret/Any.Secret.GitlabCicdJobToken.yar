// betterleaks v1.10.0's gitlab-cicd-job-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GitlabCicdJobToken
{
    meta:
        description     = "Identified a GitLab CI/CD Job Token, potential access to projects and some APIs on behalf of a user while the CI job is running."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabCicdJobToken"
        severity        = "high"
        score           = 80
        id              = "gitlab-cicd-job-token"
        confidence      = "high"
        keyword         = "glcbt-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}/  // gitleaks:allow

    condition:
        $secret
}
