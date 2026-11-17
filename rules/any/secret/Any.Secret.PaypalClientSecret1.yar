// betterleaks v1.10.0's paypal-client-secret.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_PaypalClientSecret1
{
    meta:
        description       = "PayPal OAuth client secret, which may allow access to PayPal REST APIs when paired with its client ID."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "PaypalClientSecret1"
        severity          = "high"
        score             = 80
        id                = "paypal-client-secret.1"
        confidence        = "high"
        keyword           = "paypal"
        component1        = "paypal-client-id.1"
        component1_within = "5L"
        skip_entropy_lt   = "3.5"

    strings:
        $secret = /(?:(?:[pP][aA][yY][pP][aA][lL][_.-]?(?:[cC][lL][iI][eE][nN][tT][_.-]?)?(?:[sS][eE][cC][rR][eE][tT]|[pP][rR][iI][vV][aA][tT][eE]|[aA][cC][cC][eE][sS][sS]|[kK][eE][yY]|[tT][oO][kK][eE][nN]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_.-]{78,120})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
