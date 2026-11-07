// betterleaks v1.10.0's resend-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ResendApiKey1
{
    meta:
        description     = "Resend API key, which may allow sending email or managing account resources."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ResendApiKey1"
        severity        = "high"
        score           = 80
        id              = "resend-api-key.1"
        confidence      = "high"
        keyword         = "resend"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(re_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
