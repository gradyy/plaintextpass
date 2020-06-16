"use strict";

const transformCredentialRequestOptions = (credentialRequestOptionsFromServer) => {
    let {challenge, allowCredentials} = credentialRequestOptionsFromServer;

    challenge = Uint8Array.from(
        atob(challenge.replace(/\_/g, "/").replace(/\-/g, "+")), c => c.charCodeAt(0));

    allowCredentials = allowCredentials.map(credentialDescriptor => {
        let {id} = credentialDescriptor;
        id = id.replace(/\_/g, "/").replace(/\-/g, "+");
        id = Uint8Array.from(atob(id), c => c.charCodeAt(0));
        return Object.assign({}, credentialDescriptor, {id});
    });

    const transformedCredentialRequestOptions = Object.assign(
        {},
        credentialRequestOptionsFromServer,
        {challenge, allowCredentials});

    return transformedCredentialRequestOptions;
};

/**
 * Encodes the binary data in the assertion into strings for posting to the server.
 * @param {PublicKeyCredential} newAssertion
 */
const transformAssertionForServer = (newAssertion) => {
    const authData = new Uint8Array(newAssertion.response.authenticatorData);
    const clientDataJSON = new Uint8Array(newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(newAssertion.rawId);
    const sig = new Uint8Array(newAssertion.response.signature);
    const assertionClientExtensions = newAssertion.getClientExtensionResults();

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        authData: b64RawEnc(authData),
        clientData: b64RawEnc(clientDataJSON),
        signature: hexEncode(sig),
        assertionClientExtensions: JSON.stringify(assertionClientExtensions)
    };
};

async function webauthnAuthenticateRequest(e){
    e.preventDefault();
    // gather the data in the form
    const form = e.target;
    const assertionCreateUrl = form.querySelector("#webauthnAuthenticationURL").value;
    const assertionAuthenticationUrl = form.target;
    const formData = new FormData(form);

    // post the login data to the server to retrieve the PublicKeyCredentialRequestOptions
    let credentialRequestOptionsFromServer;
    try {
        credentialRequestOptionsFromServer = await postFormToServer(
            assertionCreateUrl,
            formData
        );
    } catch (err) {
        window.location.reload();
        return console.error("Error when getting request options from server:", err);
    }

    // request the authenticator to create an assertion signature using the
    // credential private key
    let assertion;
    try {
        // convert certain members of the PublicKeyCredentialRequestOptions into
        // byte arrays as expected by the spec.
        const transformedCredentialRequestOptions = transformCredentialRequestOptions(
            credentialRequestOptionsFromServer);
        assertion = await navigator.credentials.get({
            publicKey: transformedCredentialRequestOptions,
        });
    } catch (err) {
        return console.error("Error when creating credential:", err);
    }

    // we now have an authentication assertion! encode the byte arrays contained
    // in the assertion data as strings for posting to the server
    const transformedAssertionForServer = transformAssertionForServer(assertion);

    // post the assertion to the server for verification.
    let response;
    try {
        response = await postCredentialToServer(assertionAuthenticationUrl, transformedAssertionForServer);
        if (response.success !== undefined){
            window.location.href = response.redirect;
        }
    } catch (err) {
        window.location.reload();
        return console.error("Error when validating assertion on server:", err);
    }

}
