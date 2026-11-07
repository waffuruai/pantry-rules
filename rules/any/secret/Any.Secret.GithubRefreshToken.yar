// betterleaks v1.10.0's github-refresh-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GithubRefreshToken
{
    meta:
        description     = "Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GithubRefreshToken"
        severity        = "high"
        score           = 80
        id              = "github-refresh-token"
        confidence      = "high"
        keyword         = "ghr_"
        skip_entropy_le = "3.0"

    strings:
        $secret = /ghr_[0-9a-zA-Z]{36}/  // gitleaks:allow

    condition:
        $secret
}
