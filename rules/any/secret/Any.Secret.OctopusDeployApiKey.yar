// betterleaks v1.10.0's octopus-deploy-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_OctopusDeployApiKey
{
    meta:
        description     = "Discovered a potential Octopus Deploy API key, risking application deployments and operational security."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "OctopusDeployApiKey"
        severity        = "medium"
        score           = 50
        id              = "octopus-deploy-api-key"
        confidence      = "medium"
        keyword         = "api-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(API-[A-Z0-9]{26})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
