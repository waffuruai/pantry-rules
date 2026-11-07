// betterleaks v1.10.0's mux-access-token-id.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_MuxAccessTokenId1
{
    meta:
        description     = "Mux access-token ID, used as a component of the Mux access-token-secret composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "MuxAccessTokenId1"
        severity        = "medium"
        score           = 50
        id              = "mux-access-token-id.1"
        confidence      = "medium"
        keyword         = "mux"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /(?:[mM][uU][xX][_.-]?(?:[aA][cC][cC][eE][sS][sS][_.-]?)?[tT][oO][kK][eE][nN][_.-]?(?:[iI][dD]|[iI][dD][eE][nN][tT][iI][fF][iI][eE][rR]))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
