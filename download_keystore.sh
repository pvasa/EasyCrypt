#!/usr/bin/env bash
# use curl to download a keystore from $KEYSTORE_URI, if set,
# to the path/filename set in $KEYSTORE.
if [[ ${KEYSTORE_URI} ]]
then
    echo "Keystore detected - downloading..."
    # we're using curl instead of wget because it will not
    # expose the sensitive uri in the build logs:
    curl -L -o "${HOME}/code/keystore.jks" ${KEYSTORE_URI}
else
    echo "Keystore uri not set. \".APK\" artifact will not be signed."
fi
