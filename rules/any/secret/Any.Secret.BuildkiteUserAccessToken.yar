// betterleaks v1.10.0's buildkite-user-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_BuildkiteUserAccessToken
{
    meta:
        description     = "Detected a Buildkite user access token, which may expose pipelines, builds, and organization data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "BuildkiteUserAccessToken"
        severity        = "high"
        score           = 80
        id              = "buildkite-user-access-token"
        confidence      = "high"
        keyword         = "bkua_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(bkua_(?:[a-z0-9]{40}|[a-z0-9]{53}))\b/  // gitleaks:allow

    condition:
        $secret
}
