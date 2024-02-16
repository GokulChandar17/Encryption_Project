function redirectTo(url) {
    window.location.href = url;
}


function encrypt() {
    var encryptionTechnique = document.getElementById("encryption-technique").value;
    var plaintext = document.getElementById("plaintext").value;

    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/encrypt", true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4 && xhr.status == 200) {
            var response = JSON.parse(xhr.responseText);
            document.getElementById("ciphertext-container").innerHTML = "<p>Ciphertext: " + response.ciphertext + "</p>";
        }
    };
    var data = "encryption_technique=" + encodeURIComponent(encryptionTechnique) + "&plaintext=" + encodeURIComponent(plaintext);
    xhr.send(data);
}

function decrypt() {
    var decryptionTechnique = document.getElementById("decryption-technique").value;
    var ciphertext = document.getElementById("ciphertext").value;

    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/decrypt", true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4 && xhr.status == 200) {
            var response = JSON.parse(xhr.responseText);
            document.getElementById("plaintext-container").innerHTML = "<p>Plaintext: " + response.plaintext + "</p>";
        }
    };
    var data = "decryption_technique=" + encodeURIComponent(decryptionTechnique) + "&ciphertext=" + encodeURIComponent(ciphertext);
    xhr.send(data);
}



