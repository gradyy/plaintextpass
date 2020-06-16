"use strict";
function b64enc(buf) {
    return base64js.fromByteArray(buf)
                   .replace(/\+/g, "-")
                   .replace(/\//g, "_")
                   .replace(/=/g, "");
}

function b64RawEnc(buf) {
    return base64js.fromByteArray(buf)
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function hexEncode(buf) {
    return Array.from(buf)
                .map(function(x) {
                    return ("0" + x.toString(16)).substr(-2);
                })
                .join("");
}

/**
 * Get PublicKeyCredentialRequestOptions for this user from the server
 * destination specifies the url of the handler
 * "webauthn_begin_activate" for registration handler
 * "webauthn_begin_assertion" for authentication handler
 * formData of the registration or authentication form
 * @param {string} destination
 * @param {FormData} formData
 */
const postFormToServer = (destination, formData) => {
    return fetch(
            destination,
            {
                method: "POST",
                body: formData
            }
    )
    .then((response) => response.json())
    .then((body) => {
        if (body.fail){
            throw body.fail;
        }
        return body;
    })
}

/**
 * Posts webauthn credential data to the server at the destination url
 * "verify_credential_info" for registration
 * Posts the new credential data to the server for validation and storage.
 * "verify_assertion" for authentication
 * Post the assertion to the server for validation and logging the user in. 
 * @param {string} destination
 * @param {Object} credentialDataForServer
 */
const postCredentialToServer = async (destination, credentialDataForServer) => {
    const formData = new FormData();
    Object.entries(credentialDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });
    return await postFormToServer(destination, formData);
}