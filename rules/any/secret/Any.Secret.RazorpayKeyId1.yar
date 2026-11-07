// betterleaks v1.10.0's razorpay-key-id.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_RazorpayKeyId1
{
    meta:
        description     = "Razorpay key ID, used as a component of the Razorpay key-secret composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "RazorpayKeyId1"
        severity        = "high"
        score           = 80
        id              = "razorpay-key-id.1"
        confidence      = "high"
        keyword         = "rzp_live_"
        keyword         = "rzp_test_"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b(rzp_(?:live|test)_[A-Za-z0-9]{14})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
