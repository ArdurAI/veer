BEGIN {
    FS = "\t"
    OFS = "\t"
    error_count = 0
}

# Record a validation error while allowing the current file to be fully checked.
function fail(message) {
    print FILENAME ":" FNR ": " message > "/dev/stderr"
    error_count++
}

# Return the final component of a slash-separated path.
function basename(path, parts, count) {
    count = split(path, parts, "/")
    return parts[count]
}

# Accept only unsigned decimal quantities; scientific notation is disallowed.
function is_amount(value) {
    return value ~ /^[0-9]+([.][0-9]+)?$/
}

{
    file = basename(FILENAME)
}

file == "sources.tsv" {
    if (FNR == 1) {
        if ($0 != "source_id\tpricing_date\tregion\turl\trate_scope") {
            fail("unexpected sources header")
        }
        next
    }

    if (NF != 5) {
        fail("source row must contain five tab-separated fields")
        next
    }
    if ($1 in sources) {
        fail("duplicate source_id " $1)
    }
    if ($2 !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) {
        fail("pricing_date must use YYYY-MM-DD")
    }
    if ($4 !~ /^https:\/\//) {
        fail("source URL must use HTTPS")
    }
    immutable_offer = "^https://pricing[.]us-east-1[.]amazonaws[.]com/" \
        "offers/v1[.]0/aws/[A-Za-z0-9]+/" \
        "[0-9][0-9][0-9][0-9][0-9][0-9][0-9]" \
        "[0-9][0-9][0-9][0-9][0-9][0-9][0-9]" \
        "(/[a-z0-9-]+)?/index[.]json$"
    if ($1 != "internal-local" && $4 !~ immutable_offer) {
        fail("billable source URL must pin an immutable AWS Offers version")
    }
    sources[$1] = 1
    next
}

file == "profiles.tsv" {
    if (FNR == 1) {
        if ($0 != "profile\tceiling_usd\tdescription") {
            fail("unexpected profiles header")
        }
        next
    }

    if (NF != 3) {
        fail("profile row must contain three tab-separated fields")
        next
    }
    if ($1 in ceilings) {
        fail("duplicate profile " $1)
    }
    if (!is_amount($2)) {
        fail("ceiling_usd must be a non-negative decimal")
    }
    ceilings[$1] = $2 + 0
    profile_order[++profile_count] = $1
    next
}

file == "inputs.tsv" {
    if (FNR == 1) {
        if ($0 != "profile\titem\tcategory\tquantity\tunit\tunit_rate_usd\tsource_id\tnote") {
            fail("unexpected inputs header")
        }
        next
    }

    if (NF != 8) {
        fail("input row must contain eight tab-separated fields")
        next
    }
    if (!($1 in ceilings)) {
        fail("unknown profile " $1)
    }
    key = $1 SUBSEP $2
    if (key in items) {
        fail("duplicate item " $1 "/" $2)
    }
    if (!is_amount($4) || !is_amount($6)) {
        fail("quantity and unit_rate_usd must be non-negative decimals")
    }
    if (!($7 in sources)) {
        fail("unknown source_id " $7)
    }
    if ($7 == "internal-local" && ($6 + 0) != 0) {
        fail("internal-local may only support a zero unit rate")
    }
    items[key] = 1
    profile_items[$1]++
    totals[$1] += ($4 + 0) * ($6 + 0)
    next
}

{
    fail("unexpected worksheet file " file)
}

END {
    if (error_count > 0) {
        exit 1
    }

    print "profile", "monthly_estimate_usd", "ceiling_usd", "headroom_usd", "headroom_percent"
    for (i = 1; i <= profile_count; i++) {
        profile = profile_order[i]
        if (profile_items[profile] == 0) {
            print "profile " profile " has no cost inputs" > "/dev/stderr"
            error_count++
        }
        estimate = totals[profile] + 0
        ceiling = ceilings[profile]
        headroom = ceiling - estimate
        if (ceiling == 0) {
            headroom_percent = "0.00"
        } else {
            headroom_percent = sprintf("%.2f", 100 * headroom / ceiling)
        }

        printf "%s\t%.2f\t%.2f\t%.2f\t%s\n",
            profile, estimate, ceiling, headroom, headroom_percent

        if (headroom < -0.0001) {
            print "profile " profile " exceeds its monthly ceiling by USD " \
                sprintf("%.2f", -headroom) > "/dev/stderr"
            error_count++
        }
    }

    if (error_count > 0) {
        exit 1
    }
}
