// betterleaks v1.10.0's github-oauth rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GithubOauth
{
    meta:
        description     = "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GithubOauth"
        severity        = "high"
        score           = 80
        id              = "github-oauth"
        confidence      = "high"
        keyword         = "gho_"
        skip_entropy_le = "3.0"

    strings:
        $secret = /gho_[0-9a-zA-Z]{36}/  // gitleaks:allow

    condition:
        $secret
}
