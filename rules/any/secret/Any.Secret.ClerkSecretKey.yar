// betterleaks v1.10.0's clerk-secret-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ClerkSecretKey
{
    meta:
        description     = "Detected a Clerk secret key, which may allow unauthorized access to Clerk backend APIs."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ClerkSecretKey"
        severity        = "medium"
        score           = 50
        id              = "clerk-secret-key"
        confidence      = "medium"
        keyword         = "clerk"
        skip_entropy_lt = "3.3"

    strings:
        $secret = /(?:[cC][lL][eE][rR][kK])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([sS][kK]_(?:[tT][eE][sS][tT]|[lL][iI][vV][eE])_[a-zA-ZA-Za-z0-9]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
