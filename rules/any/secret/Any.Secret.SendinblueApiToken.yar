// betterleaks v1.10.0's sendinblue-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_SendinblueApiToken
{
    meta:
        description     = "Identified a Brevo (formerly Sendinblue) API token, which may compromise email marketing services and subscriber data privacy."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SendinblueApiToken"
        severity        = "high"
        score           = 80
        id              = "sendinblue-api-token"
        confidence      = "high"
        keyword         = "xkeysib-"
        skip_entropy_lt = "3.2"

    strings:
        $secret = /\b(xkeysib-[a-fA-F0-9]{64}-[a-zA-Z0-9]{16})\b/  // gitleaks:allow

    condition:
        $secret
}
