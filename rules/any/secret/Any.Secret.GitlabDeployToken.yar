// betterleaks v1.10.0's gitlab-deploy-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GitlabDeployToken
{
    meta:
        description     = "Identified a GitLab Deploy Token, risking access to repositories, packages and containers with write access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabDeployToken"
        severity        = "high"
        score           = 80
        id              = "gitlab-deploy-token"
        confidence      = "high"
        keyword         = "gldt-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /gldt-[0-9a-zA-Z_\-]{20}/  // gitleaks:allow

    condition:
        $secret
}
