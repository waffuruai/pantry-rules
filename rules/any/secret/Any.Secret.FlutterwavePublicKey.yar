// betterleaks v1.10.0's flutterwave-public-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_FlutterwavePublicKey
{
    meta:
        description     = "Detected a Flutterwave Public Key, potentially exposing public cryptographic operations and integrations."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "FlutterwavePublicKey"
        severity        = "high"
        score           = 80
        id              = "flutterwave-public-key"
        confidence      = "high"
        keyword         = "flwpubk_test"
        skip_entropy_le = "2.0"

    strings:
        $secret = /FLWPUBK_TEST-[A-Ha-h0-9]{32}-[Xx]/  // gitleaks:allow

    condition:
        $secret
}
