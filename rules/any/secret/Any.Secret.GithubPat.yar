// betterleaks v1.10.0's github-pat rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GithubPat
{
    meta:
        description     = "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GithubPat"
        severity        = "high"
        score           = 80
        id              = "github-pat"
        confidence      = "high"
        keyword         = "ghp_"
        skip_entropy_le = "3.0"
        skip_regex_path = "(?:^|/)@octokit/auth-token/README\\.md$"  // gitleaks:allow

    strings:
        $secret = /ghp_[0-9a-zA-Z]{36}/  // gitleaks:allow

    condition:
        $secret
}
