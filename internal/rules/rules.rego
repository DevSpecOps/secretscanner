package secretscanner

default detect = {"matched": false, "rule_id": ""}

detect = {"matched": true, "rule_id": "AWS001"} {
    regex.match(`AKIA[0-9A-Z]{16}`, input.line)
}

detect = {"matched": true, "rule_id": "RSA001"} {
    contains(input.line, "BEGIN RSA PRIVATE KEY")
}

detect = {"matched": true, "rule_id": "GHPAT001"} {
    regex.match(`github_pat_[A-Za-z0-9_]{22,}`, input.line)
}