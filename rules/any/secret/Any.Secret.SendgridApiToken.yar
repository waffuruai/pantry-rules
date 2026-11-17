// betterleaks v1.10.0's sendgrid-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_SendgridApiToken
{
    meta:
        description     = "Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SendgridApiToken"
        severity        = "high"
        score           = 80
        id              = "sendgrid-api-token"
        confidence      = "high"
        keyword         = "sg."
        skip_entropy_le = "2.0"

    strings:
        $secret = /\b(SG\.[A-Za-z0-9=_\-\.]{66})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
