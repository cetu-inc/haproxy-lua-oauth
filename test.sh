#!/bin/bash

# Function to wait for containers to be up
wait_for_containers() {
    # Wait for at least two containers to be up and running
    echo "Waiting for at least 2 containers to be running..."
    while true; do
        container_count=$(docker compose -f "$COMPOSE_FILE" ps -q | wc -l)
        if [ "$container_count" -ge 2 ]; then
            echo "At least 2 containers are running."
            break
        fi
        echo "Currently $container_count containers are running. Waiting..."
        sleep 2  # Wait for 2 seconds before checking again
    done

    # Now check each container's status
    local service_names=$(docker compose -f "$COMPOSE_FILE" ps --services)
    for service in $service_names; do
        echo "Waiting for $service to be up..."
        while true; do
            status=$(docker compose -f "$COMPOSE_FILE" ps "$service" | grep "$service" | grep "Up")
            if [ -n "$status" ]; then
                echo "$service is up!"
                break
            fi
            sleep 2  # Wait for 2 seconds before checking again
        done
    done
}

# Log function with color and timestamp
log() {
    local GREEN="\033[0;32m"
    local YELLOW="\033[1;33m"
    local RED="\033[0;31m"
    local NC="\033[0m"  # No Color

    # Get log level and message
    local log_level=$1
    shift
    local log_message="$@"

    # Get current date and time
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # Set color based on log level
    case $log_level in
        DEBUG)
            echo -e "${NC}[$timestamp] [INFO] ${log_message}${NC}"
            ;;
        INFO)
            echo -e "${GREEN}[$timestamp] [INFO] ${log_message}${NC}"
            ;;
        WARNING)
            echo -e "${YELLOW}[$timestamp] [WARNING] ${log_message}${NC}"
            ;;
        ERROR)
            echo -e "${RED}[$timestamp] [ERROR] ${log_message}${NC}"
            ;;
        *)
            echo -e "[$timestamp] [UNKNOWN] ${log_message}"
            ;;
    esac
}

base64_url_encode() {
    openssl base64 -e -A | tr '+/' '-_' | tr -d '='
}

create_jwt() {
    local header=$1
    local payload=$2
    local private_key=$3

    local encoded_header=$(echo -n "$header" | base64_url_encode)
    local encoded_payload=$(echo -n "$payload" | base64_url_encode)

    local unsigned_token="${encoded_header}.${encoded_payload}"
    local signature=$(echo -n "$unsigned_token" | openssl dgst -sha256 -sign "$private_key" | base64_url_encode)

    echo "${unsigned_token}.${signature}"
}

# Constants
WORKDIR="$(pwd)"
TMP_DIR="${WORKDIR}/tmp"
PRIVATE_KEY="${TMP_DIR}/private.pem"
PUBLIC_KEY="${TMP_DIR}/public.pem"
CERT_FILE="${TMP_DIR}/cert.pem"
PRIVATE2_KEY="${TMP_DIR}/private2.pem"
PUBLIC2_KEY="${TMP_DIR}/public2.pem"
CERT2_FILE="${TMP_DIR}/cert2.pem"
COMPOSE_FILE="${WORKDIR}/docker-compose.ubuntu.example.yml"

mkdir -p ${TMP_DIR}

## Setup
generate_keys() {
    log INFO "Generating keys..."
    openssl req -x509 \
        -newkey rsa:4096 \
        -keyout "${PRIVATE_KEY}" \
        -out "${CERT_FILE}" \
        -days 365 \
        -nodes \
        -subj "/CN=youraccount.auth0.com"
    openssl x509 -pubkey -noout -in "${CERT_FILE}" > "${PUBLIC_KEY}"
    openssl req -x509 \
        -newkey rsa:4096 \
        -keyout "${PRIVATE2_KEY}" \
        -out "${CERT2_FILE}" \
        -days 365 \
        -nodes \
        -subj "/CN=youraccount.auth0.com"
    openssl x509 -pubkey -noout -in "${CERT2_FILE}" > "${PUBLIC2_KEY}"
}

generate_keys


log INFO "Overriding the public key used to verify the signature"
cp "${PUBLIC_KEY}" "${WORKDIR}/example/haproxy/pem/pubkey.pem"
cp "${PUBLIC2_KEY}" "${WORKDIR}/example/haproxy/pem/pubkey2.pem"

log info "Take down any old project"
docker compose -f ${COMPOSE_FILE} down || true

log INFO "Start the compose project"
docker compose -f ${COMPOSE_FILE} up -d
docker compose -f ${COMPOSE_FILE} logs -f &

log INFO "Waiting for containers to go up"
wait_for_containers

###### Tests ######
test_sanity() {
    # Header for RS256 JWT
    header='{
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key1"
    }'

    log DEBUG Payload \(modify as needed\)
    payload='{
    "iss": "https://youraccount.auth0.com/",
    "aud": "https://api.mywebsite.com",
    "sub": "user@example.com",
    "exp": '$(($(date +%s) + 3600))',
    "scope": "read:myapp"
    }'

    log DEBUG Create jwt
    jwt=$(create_jwt "$header" "$payload" "$PRIVATE_KEY")

    log DEBUG "Testing the API"
    curl --request GET \
        -k --fail \
        --url https://localhost/api/myapp \
        --header "authorization: Bearer ${jwt}"

    # We expect the API to pass
    [[ $? -eq 0 ]]
}

test_no_audience() {
    # Header for RS256 JWT
    header='{
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key1"
    }'

    log DEBUG Payload \(modify as needed\)
    payload='{
    "iss": "https://youraccount.auth0.com/",
    "sub": "user@example.com",
    "exp": '$(($(date +%s) + 3600))',
    "scope": "read:myapp"
    }'

    log DEBUG Create jwt
    jwt=$(create_jwt "$header" "$payload" "$PRIVATE_KEY")

    log DEBUG "Testing the API"
    curl --request GET \
        -k --fail \
        --url https://localhost/api/myapp \
        --header "authorization: Bearer ${jwt}"

    # We expect the API to return an error
    [[ $? -ne 0 ]]
}

test_incorrect_key_id() {
    # Header for RS256 JWT
    header='{
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key195"
    }'

    log DEBUG Payload \(modify as needed\)
    payload='{
    "iss": "https://youraccount.auth0.com/",
    "aud": "https://api.mywebsite.com",
    "sub": "user@example.com",
    "exp": '$(($(date +%s) + 3600))',
    "scope": "read:myapp"
    }'

    log DEBUG Create jwt
    jwt=$(create_jwt "$header" "$payload" "$PRIVATE_KEY")

    log DEBUG "Testing the API"
    curl --request GET \
        -k --fail \
        --url https://localhost/api/myapp \
        --header "authorization: Bearer ${jwt}"

    # We expect the API to return an error
    [[ $? -ne 0 ]]
}

test_second_key_usage_pass() {
    # Header for RS256 JWT
    header='{
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key2"
    }'

    log DEBUG Payload \(modify as needed\)
    payload='{
    "iss": "https://youraccount.auth0.com/",
    "aud": "https://api.mywebsite.com",
    "sub": "user@example.com",
    "exp": '$(($(date +%s) + 3600))',
    "scope": "read:myapp"
    }'

    log DEBUG Create jwt
    jwt=$(create_jwt "$header" "$payload" "$PRIVATE2_KEY")

    log DEBUG "Testing the API"
    curl --request GET \
        -k --fail \
        --url https://localhost/api/myapp \
        --header "authorization: Bearer ${jwt}"

    # We expect the API to pass
    [[ $? -eq 0 ]]
}

test_second_key_usage_fail() {
    # Header for RS256 JWT
    header='{
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key"
    }'

    log DEBUG Payload \(modify as needed\)
    payload='{
    "iss": "https://youraccount.auth0.com/",
    "aud": "https://api.mywebsite.com",
    "sub": "user@example.com",
    "exp": '$(($(date +%s) + 3600))',
    "scope": "read:myapp"
    }'

    log DEBUG Create jwt
    jwt=$(create_jwt "$header" "$payload" "$PRIVATE2_KEY")

    log DEBUG "Testing the API"
    curl --request GET \
        -k --fail \
        --url https://localhost/api/myapp \
        --header "authorization: Bearer ${jwt}"

    # We expect the API to return an error
    [[ $? -ne 0 ]]
}

###### Run tests ######
# Define the array of test functions
tests=("test_sanity" "test_no_audience" "test_incorrect_key_id" "test_second_key_usage_pass" "test_second_key_usage_fail")
all_tests_passed=true

# Loop through the array of test functions and run them
for test in "${tests[@]}"; do
    log INFO "Running $test..."
    $test  # Call the test function

    # Check the result of the test
    if [ $? -eq 0 ]; then
        log INFO "$test passed"
    else
        log ERROR "$test failed"
        all_tests_passed=false
    fi
done

# Terminate the compose project
log INFO "Take down any old project"
docker compose -f ${COMPOSE_FILE} down || true

# Check if all tests passed
if [ "$all_tests_passed" = true ]; then
    log INFO "All tests passed. The run was successful."
    exit 0
else
    log ERROR "Some tests failed. The run failed."
    exit 1
fi