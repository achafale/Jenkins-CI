# Setting the evnironment variables
NSPECT_ID="NSPECT-76DN-OP7I"

# Run the curl command and capture the output
json_output=$(curl --location --request POST 'https://x9thwm-cootr2q1jdv5p7b8iw4fs4ob3x6nqqsoznyk.ssa.nvidia.com/token' \
  --user 'nvssa-prd-4tRcjNpunCJVFgVq7o1iYtC9pWIX-RxopTGdLecMinQ:ssap-t2eWZXICpejIVJ7' \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'scope=nspect.verify scan.anchore')

echo "Done fetching access token ..."

# Extract the access_token using jq
SSA_TOKEN=$(echo $json_output | jq -r '.access_token')

echo "Done generating access token ..."

CONTAINER_ARCHIVE="rc_1_build.tar"
CONTAINER_SCAN_POLICY="policy.json"

# docker save hello-world > hello.tar

echo "Done creating container archive ..."

echo "NSPECT_ID=$NSPECT_ID" > .env
echo "SSA_TOKEN=$SSA_TOKEN" >> .env
echo "CONTAINER_ARCHIVE=$CONTAINER_ARCHIVE" >> .env
echo "CONTAINER_SCAN_POLICY=$CONTAINER_SCAN_POLICY" >> .env

echo "Running the pulse scan ..."

docker run --rm -it --env-file .env -v ${PWD}:/dist -w /dist gitlab-master.nvidia.com:5005/pstooling/pulse-group/pulse-container-scanner/pulse-cli:stable /bin/sh -c "pulse-cli -n $NSPECT_ID --ssa $SSA_TOKEN scan -i $CONTAINER_ARCHIVE -p $CONTAINER_SCAN_POLICY -o"
