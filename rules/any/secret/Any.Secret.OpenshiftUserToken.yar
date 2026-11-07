// betterleaks v1.10.0's openshift-user-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_OpenshiftUserToken
{
    meta:
        description     = "Found an OpenShift user token, potentially compromising an OpenShift/Kubernetes cluster."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "OpenshiftUserToken"
        severity        = "high"
        score           = 80
        id              = "openshift-user-token"
        confidence      = "high"
        keyword         = "sha256~"
        skip_entropy_le = "3.5"

    strings:
        $secret = /\b(sha256~[\w-]{43})(?:[^\w-]|$)/  // gitleaks:allow

    condition:
        $secret
}
