// betterleaks v1.10.0's github-fine-grained-pat rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_GithubFineGrainedPat
{
    meta:
        description     = "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "GithubFineGrainedPat"
        severity        = "high"
        score           = 80
        id              = "github-fine-grained-pat"
        confidence      = "high"
        keyword         = "github_pat_"
        skip_entropy_le = "3.0"

    strings:
        $secret = /github_pat_\w{82}/  // gitleaks:allow

    condition:
        $secret
}
