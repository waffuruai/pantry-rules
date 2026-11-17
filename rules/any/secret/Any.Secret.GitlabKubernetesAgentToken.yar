// betterleaks v1.10.0's gitlab-kubernetes-agent-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_GitlabKubernetesAgentToken
{
    meta:
        description     = "Identified a GitLab Kubernetes Agent token, risking access to repos and registry of projects connected via agent."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GitlabKubernetesAgentToken"
        severity        = "high"
        score           = 80
        id              = "gitlab-kubernetes-agent-token"
        confidence      = "high"
        keyword         = "glagent-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /glagent-[0-9a-zA-Z_\-]{50}/  // gitleaks:allow

    condition:
        $secret
}
