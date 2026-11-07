// betterleaks v1.10.0's mux-access-token-secret.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_MuxAccessTokenSecret1
{
    meta:
        description       = "Mux access-token secret, which may grant access to video, data, or system APIs when paired with its token ID."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "MuxAccessTokenSecret1"
        severity          = "high"
        score             = 80
        id                = "mux-access-token-secret.1"
        confidence        = "high"
        keyword           = "mux"
        component1        = "mux-access-token-id.1"
        component1_within = "5L"
        skip_entropy_lt   = "3.5"

    strings:
        $secret = /(?:(?:[mM][uU][xX][_.-]?(?:[aA][cC][cC][eE][sS][sS][_.-]?)?[tT][oO][kK][eE][nN][_.-]?(?:[sS][eE][cC][rR][eE][tT]|[pP][rR][iI][vV][aA][tT][eE]|[kK][eE][yY]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9+\/]{75})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
