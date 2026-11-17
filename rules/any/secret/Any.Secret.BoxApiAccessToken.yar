// betterleaks v1.10.0's box-api-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
//
// Its filter, a program Pantry runs as written (filter_expr):
//
// let prefix = filter.findMatch(finding["fragment_raw"][finding["match_line_start_idx"]:finding["match_start_idx"]], "[\\w.-]*$");
// let identifier = prefix + filter.findMatch(finding["match"], "^[\\w .-]+");
// lower(identifier) contains "client" || entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_BoxApiAccessToken
{
    meta:
        description = "Detected a Box API access token, which may expose Box files and account data."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "BoxApiAccessToken"
        severity    = "medium"
        score       = 50
        id          = "box-api-access-token"
        confidence  = "medium"
        keyword     = "box_"
        keyword     = "box-"
        keyword     = "boxt"
        keyword     = "boxk"
        keyword     = "boxa"
        filter_expr = "let prefix = filter.findMatch(finding[\"fragment_raw\"][finding[\"match_line_start_idx\"]:finding[\"match_start_idx\"]], \"[\\\\w.-]*$\");\nlet identifier = prefix + filter.findMatch(finding[\"match\"], \"^[\\\\w .-]+\");\nlower(identifier) contains \"client\" || entropy(finding[\"secret\"]) < 3.5 || filter.tokenRatio(finding[\"secret\"]) >= 2.5"

    strings:
        $secret = /(?:[bB][oO][xX])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
