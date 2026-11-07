// betterleaks v1.10.0's razorpay-key-secret.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_RazorpayKeySecret1
{
    meta:
        description       = "Razorpay key secret, which may authorize payment APIs when paired with its key ID."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "RazorpayKeySecret1"
        severity          = "high"
        score             = 80
        id                = "razorpay-key-secret.1"
        confidence        = "high"
        keyword           = "razorpay"
        component1        = "razorpay-key-id.1"
        component1_within = "5L"
        skip_entropy_lt   = "3.0"

    strings:
        $secret = /(?:(?:[rR][aA][zZ][oO][rR][pP][aA][yY][_.-]?(?:(?:[aA][pP][iI]|[kK][eE][yY])[_.-]?)?(?:[sS][eE][cC][rR][eE][tT]|[pP][rR][iI][vV][aA][tT][eE]|[tT][oO][kK][eE][nN]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{24})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
