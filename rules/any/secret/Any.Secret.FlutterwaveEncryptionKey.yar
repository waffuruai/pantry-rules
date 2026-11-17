// betterleaks v1.10.0's flutterwave-encryption-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_FlutterwaveEncryptionKey
{
    meta:
        description     = "Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "FlutterwaveEncryptionKey"
        severity        = "high"
        score           = 80
        id              = "flutterwave-encryption-key"
        confidence      = "high"
        keyword         = "flwseck_test"
        skip_entropy_le = "2.0"

    strings:
        $secret = /FLWSECK_TEST-[A-Ha-h0-9]{12}/  // gitleaks:allow

    condition:
        $secret
}
