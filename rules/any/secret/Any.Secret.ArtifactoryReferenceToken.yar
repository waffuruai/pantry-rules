// betterleaks v1.10.0's artifactory-reference-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ArtifactoryReferenceToken
{
    meta:
        description     = "Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ArtifactoryReferenceToken"
        severity        = "high"
        score           = 80
        id              = "artifactory-reference-token"
        confidence      = "high"
        keyword         = "cmvmd"
        component1      = "artifactory-jfrog-url"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\bcmVmd[A-Za-z0-9]{59}\b/  // gitleaks:allow

    condition:
        $secret
}
