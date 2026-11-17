// betterleaks v1.10.0's postman-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_PostmanApiToken
{
    meta:
        description     = "Uncovered a Postman API token, potentially compromising API testing and development workflows."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PostmanApiToken"
        severity        = "high"
        score           = 80
        id              = "postman-api-token"
        confidence      = "high"
        keyword         = "pmak-"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(PMAK-[A-Fa-f0-9]{24}\-[A-Fa-f0-9]{34})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
