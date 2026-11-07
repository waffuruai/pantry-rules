// betterleaks v1.10.0's 1password-secret-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_1passwordSecretKey
{
    meta:
        description     = "Uncovered a possible 1Password secret key, potentially compromising access to secrets in vaults."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "1passwordSecretKey"
        severity        = "high"
        score           = 80
        id              = "1password-secret-key"
        confidence      = "high"
        keyword         = "a3-"
        skip_entropy_le = "3.8"

    strings:
        $secret = /\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b/  // gitleaks:allow

    condition:
        $secret
}
