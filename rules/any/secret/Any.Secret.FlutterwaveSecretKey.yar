// betterleaks v1.10.0's flutterwave-secret-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_FlutterwaveSecretKey
{
    meta:
        description     = "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "FlutterwaveSecretKey"
        severity        = "high"
        score           = 80
        id              = "flutterwave-secret-key"
        confidence      = "high"
        keyword         = "flwseck_test"
        skip_entropy_le = "2.0"

    strings:
        $secret = /FLWSECK_TEST-[A-Ha-h0-9]{32}-[Xx]/  // gitleaks:allow

    condition:
        $secret
}
