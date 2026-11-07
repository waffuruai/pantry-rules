// betterleaks v1.10.0's gitlab-runner-authentication-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GitlabRunnerAuthenticationToken
{
    meta:
        description     = "Discovered a GitLab Runner Authentication Token, posing a risk to CI/CD pipeline integrity and unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabRunnerAuthenticationToken"
        severity        = "high"
        score           = 80
        id              = "gitlab-runner-authentication-token"
        confidence      = "high"
        keyword         = "glrt-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /glrt-[0-9a-zA-Z_\-]{20}/  // gitleaks:allow

    condition:
        $secret
}
