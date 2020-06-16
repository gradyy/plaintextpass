
document.addEventListener("DOMContentLoaded", e => {
    for (item of document.querySelectorAll("#password")) {
        item.addEventListener('click', 
                (e) => {
                    let passwordInput = e.target;
                    if (passwordInput.type === "password") {
                        passwordInput.type = "text";                        
                    } else {
                        passwordInput.type = "password"; 
                    }
                }
            );
    };
});