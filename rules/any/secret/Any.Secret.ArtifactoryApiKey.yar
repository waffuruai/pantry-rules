// betterleaks v1.10.0's artifactory-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ArtifactoryApiKey
{
    meta:
        description     = "Detected an Artifactory api key, posing a risk unauthorized access to the central repository."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ArtifactoryApiKey"
        severity        = "high"
        score           = 80
        id              = "artifactory-api-key"
        confidence      = "high"
        keyword         = "akcp"
        component1      = "artifactory-jfrog-url"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\bAKCp[A-Za-z0-9]{68,70}\b/  // gitleaks:allow

    condition:
        $secret
}
