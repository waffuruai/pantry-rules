// betterleaks v1.10.0's woocommerce-consumer-secret.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_WoocommerceConsumerSecret1
{
    meta:
        description     = "WooCommerce REST API consumer secret, which may allow read or write access to a store with the associated consumer key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "WoocommerceConsumerSecret1"
        severity        = "high"
        score           = 80
        id              = "woocommerce-consumer-secret.1"
        confidence      = "high"
        keyword         = "wooc"
        keyword         = "woo-"
        keyword         = "woo_"
        keyword         = "cs_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:[wW][oO][oO])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([cC][sS]_[A-Fa-f0-9]{40})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
