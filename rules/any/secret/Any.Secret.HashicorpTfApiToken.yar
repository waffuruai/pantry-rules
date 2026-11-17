// betterleaks v1.10.0's hashicorp-tf-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_HashicorpTfApiToken
{
    meta:
        description     = "Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "HashicorpTfApiToken"
        severity        = "high"
        score           = 80
        id              = "hashicorp-tf-api-token"
        confidence      = "high"
        keyword         = "atlasv1"
        skip_entropy_le = "3.5"

    strings:
        $secret = /[A-Za-z0-9]{14}\.(?:atlasv1)\.[A-Za-z0-9\-_=]{60,70}/  // gitleaks:allow

    condition:
        $secret
}
