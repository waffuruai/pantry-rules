// betterleaks v1.10.0's ionic-personal-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_IonicPersonalAccessToken
{
    meta:
        description     = "Ionic personal access token."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "IonicPersonalAccessToken"
        severity        = "high"
        score           = 80
        id              = "ionic-personal-access-token"
        confidence      = "high"
        keyword         = "ionic"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(ion_[A-Za-z0-9]{42})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
