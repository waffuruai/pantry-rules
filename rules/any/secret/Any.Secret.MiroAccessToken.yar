// betterleaks v1.10.0's miro-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_MiroAccessToken
{
    meta:
        description     = "Detected a Miro OAuth access token, which may allow unauthorized access to Miro users, teams, boards, and content."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "MiroAccessToken"
        severity        = "high"
        score           = 80
        id              = "miro-access-token"
        confidence      = "high"
        keyword         = "miro"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(eyJtaXJv[A-Za-z0-9-]{10,64}_[A-Za-z0-9_-]{20,64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
