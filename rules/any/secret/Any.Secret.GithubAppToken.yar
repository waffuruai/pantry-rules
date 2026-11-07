// betterleaks v1.10.0's github-app-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GithubAppToken
{
    meta:
        description     = "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GithubAppToken"
        severity        = "high"
        score           = 80
        id              = "github-app-token"
        confidence      = "high"
        keyword         = "ghu_"
        keyword         = "ghs_"
        skip_entropy_le = "3.0"
        skip_regex_path = "(?:^|/)@octokit/auth-token/README\\.md$"  // gitleaks:allow

    strings:
        $secret = /(?:ghu|ghs)_[0-9a-zA-Z]{36}/  // gitleaks:allow

    condition:
        $secret
}
