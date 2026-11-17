// betterleaks v1.10.0's 1password-service-account-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_1passwordServiceAccountToken
{
    meta:
        description     = "Uncovered a possible 1Password service account token, potentially compromising access to secrets in vaults."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "1passwordServiceAccountToken"
        severity        = "high"
        score           = 80
        id              = "1password-service-account-token"
        confidence      = "high"
        keyword         = "ops_eyj"
        skip_entropy_le = "4.0"

    strings:
        $secret = /ops_eyJ[a-zA-Z0-9+\/]{250,}={0,3}/  // gitleaks:allow

    condition:
        $secret
}
