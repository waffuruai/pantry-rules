// betterleaks v1.10.0's paypal-client-id.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_PaypalClientId1
{
    meta:
        description     = "PayPal OAuth client ID, used as a component of the PayPal client-secret composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PaypalClientId1"
        severity        = "medium"
        score           = 50
        id              = "paypal-client-id.1"
        confidence      = "medium"
        keyword         = "paypal"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:(?:[pP][aA][yY][pP][aA][lL][_.-]?(?:[cC][lL][iI][eE][nN][tT][_.-]?)?(?:[iI][dD]|[uU][sS][eE][rR]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(A[A-Za-z0-9_-]{78,99})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
