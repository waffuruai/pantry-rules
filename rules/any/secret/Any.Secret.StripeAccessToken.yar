// betterleaks v1.10.0's stripe-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_StripeAccessToken
{
    meta:
        description       = "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "StripeAccessToken"
        severity          = "high"
        score             = 80
        id                = "stripe-access-token"
        confidence        = "high"
        keyword           = "sk_test"
        keyword           = "sk_live"
        keyword           = "sk_prod"
        keyword           = "rk_test"
        keyword           = "rk_live"
        keyword           = "rk_prod"
        skip_regex_secret = "^sk_live_a2V5Xz"  // gitleaks:allow
        skip_entropy_le   = "2.0"

    strings:
        $secret = /\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
