#!/bin/bash
# Finds expected version of a crate in another crate's Cargo.toml file
get_crate_expected_version_number()
{
    local crate_name=$1
    local crate_to_look_for_version=$2

    local cargo_toml_file="$crate_name/Cargo.toml"
    # Issue #174. The script is looking for multiple entries if the dependency is listed multiple times
    local expected_version=$(grep "$crate_to_look_for_version = " $cargo_toml_file | tr -d '{^}' | awk -F '[,:=]' '{print $5}' | head -n 1 | tr -d '{ }')
    echo $expected_version
}

# Get published versions of a crate from https://github.com/rust-lang/crates.io-index/
get_crate_published_versions()
{
    local crate_index_url=$1

    local published_versions=$(
        curl -sS "$crate_index_url" | jq .vers
    )
    echo "$published_versions"
}

# Wait for a specific akd version to be published to crates.io.
# See https://github.com/novifinancial/akd/issues/116.
# Must be run in the project root folder.
akd_version_expected=$(get_crate_expected_version_number "akd_mysql" "akd")
echo "AKD expected version in AKD_MYSQL:" $akd_version_expected
wait_time=1
while sleep $wait_time;
do
    akd_versions_published=$(
        get_crate_published_versions "https://raw.githubusercontent.com/rust-lang/crates.io-index/master/3/a/akd"
    )
    echo "AKD published versions:" $akd_versions_published
    # Check whether published versions contain the expected version
    if [[ $akd_versions_published == *"$akd_version_expected"* ]]; then
        echo "Expected version has been published."
        break
    fi
    echo "Expected version has not been published. Retrying after a wait."
    wait_time=$((wait_time+1))
    if [[ $wait_time == 42 ]]; then
	echo "Gave up."
        break
    fi
done
