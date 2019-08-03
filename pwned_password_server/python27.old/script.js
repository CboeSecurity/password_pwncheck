var passwordForm = document.getElementById('password-form');
var pwdField = document.getElementById('password-field');
var submitBtn = document.getElementById('submit-button');
var msgWrapper = document.getElementById('message-wrapper');

passwordForm.addEventListener('submit', submitValidation);
// pwdField.addEventListener('input', handleFieldChange);

function handleFieldChange(event) {
    var inputVal = event.target.value;
    if (inputVal.length >= 15) {
        submitBtn.disabled = false;
    } else {
        if (!submitBtn.disabled) submitBtn.disabled = true;
    }
}

function submitValidation(event) {
    event.preventDefault();
    msgWrapper.innerHTML = '';
    console.log('requesting');
    var pwd = document.getElementById('password-field').value;
    var data = 'u=pwdCheckUser&p=' + pwd;
    sendRequest(data);
}

function sendRequest(data) {
    var xhr = new XMLHttpRequest();
    xhr.addEventListener('readystatechange', function() {
        if (this.readyState === 4) {
            var response = parseResponse(this.responseText);
            var msgWrapper = document.getElementById('message-wrapper');

            response.messages.forEach(function(msg) {
                var newMsg = document.createTextNode(msg);
                var msgBox = document.createElement('p');
                msgBox.classList.add('msg-box', response.status ? 'success-msg' : 'error-msg');
                msgBox.appendChild(newMsg);
                msgWrapper.appendChild(msgBox);
            });

        } else {
        }
    });
    xhr.open('POST', '/checkpwd');
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send(data);
}

function parseResponse(res) {
    var pattern = /([^,]*),([^,]*),((?:.|\n)*)/;
    var parsed = pattern.exec(res);
    var status = parsed[1];
    var messages = parsed[3].split('\n');
    if (status === 'False') {
        status = false;
    } else if (status === 'True') {
        status = true;
    }
    return { status: status, messages: messages }
}

function toggleVisibility() {
    var x = document.getElementById("password-field");
    if (x.type === "password") {
        x.type = "text";
    } else {
        x.type = "password";
    }
}
