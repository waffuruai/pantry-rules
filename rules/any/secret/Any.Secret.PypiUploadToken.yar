// betterleaks v1.10.0's pypi-upload-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_PypiUploadToken
{
    meta:
        description     = "Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PypiUploadToken"
        severity        = "high"
        score           = 80
        id              = "pypi-upload-token"
        confidence      = "high"
        keyword         = "pypi-ageichlwas5vcmc"
        skip_entropy_le = "3.0"

    strings:
        $secret = /pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}/  // gitleaks:allow

    condition:
        $secret
}
