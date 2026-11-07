// betterleaks v1.10.0's artifactory-jfrog-url rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_ArtifactoryJfrogUrl
{
    meta:
        description     = "Detected a JFrog Artifactory host, used as a component of Artifactory token validation."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ArtifactoryJfrogUrl"
        severity        = "high"
        score           = 80
        id              = "artifactory-jfrog-url"
        confidence      = "high"
        keyword         = "jfrog.io"
        skip_entropy_lt = "2.5"

    strings:
        $secret = /(?:^|[^A-Za-z0-9-])([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.[jJ][fF][rR][oO][gG]\.[iI][oO])(?:$|[^A-Za-z0-9-])/  // gitleaks:allow

    condition:
        $secret
}
