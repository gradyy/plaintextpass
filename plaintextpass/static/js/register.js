"use strict";

/**
 * Transforms items in the credentialCreateOptions generated on the server
 * into byte arrays expected by the navigator.credentials.create() call
 * @param {Object} credentialCreateOptionsFromServer 
 */
const transformCredentialCreateOptions = (credentialCreateOptionsFromServer) => {
    let {challenge, user} = credentialCreateOptionsFromServer;
    user.id = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.user.id
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ), 
        c => c.charCodeAt(0));

    challenge = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.challenge
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ),
        c => c.charCodeAt(0));
    
    const transformedCredentialCreateOptions = Object.assign(
            {}, credentialCreateOptionsFromServer,
            {challenge, user});

    return transformedCredentialCreateOptions;
}

/**
 * Transforms the binary data in the credential into base64 strings
 * for posting to the server.
 * @param {PublicKeyCredential} newAssertion 
 */
const transformNewAssertionForServer = (newAssertion) => {
    const attObj = new Uint8Array(
        newAssertion.response.attestationObject);
    const clientDataJSON = new Uint8Array(
        newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(
        newAssertion.rawId);
    
    const registrationClientExtensions = newAssertion.getClientExtensionResults();

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        attObj: b64enc(attObj),
        clientData: b64enc(clientDataJSON),
        registrationClientExtensions: JSON.stringify(registrationClientExtensions)
    };
}

async function webauthnCredentialCreate(e){
    e.preventDefault();

    const form = e.target;
    const credentialCreateUrl = form.querySelector("#webauthnRegistrationURL").value;
    const registerCredentialUrl = form.target;
    const formData = new FormData(form);
    // post the data to the server to generate the
    // PublicKeyCredentialCreateOptions

    let credentialCreateOptionsFromServer;
    try {
        credentialCreateOptionsFromServer = await postFormToServer(
                credentialCreateUrl,
                formData
        );
    } catch (err) {
        window.location.reload();
        return console.error("Failed to generate credential request options:", err);
    }
    let userCredential;
    try {
//      console.log(credentialCreateOptionsFromServer);
//      console.log(credentialCreateOptionsFromServer.user.id);
        let publicKeyCredentialCreateOptions = transformCredentialCreateOptions(credentialCreateOptionsFromServer);
//      console.log(credentialCreateOptionsFromServer.user.id);
        userCredential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreateOptions
        });
    } catch (err) {
        return console.error("Failed to create credential from Webauthn device", err);
    }

    // 3
    let registrationResponse;
    try {
        let credentialsForServer = transformNewAssertionForServer(userCredential);
        registrationResponse = await postCredentialToServer(registerCredentialUrl, credentialsForServer);
        if (registrationResponse.success !== undefined){
            window.location.href = registrationResponse.redirect;
        }
    } catch (err){
        window.location.reload();
        return console.error("Server rejected our credential", err);
    }
    return false;
}
