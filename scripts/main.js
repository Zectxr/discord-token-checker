let resForCopy;
async function checkTokens() {
	var token_input = document.getElementsByClassName("input_main")[0];
	var tokens = token_input.value.split('\n').map(t => t.trim()).filter(t => t);
	var resultsDiv = document.getElementById("results");
	resultsDiv.innerHTML = ''; // Clear previous results
	updateCounts();

	if (tokens.length === 0) {
		resultsDiv.innerHTML = '<span class="alert">No tokens provided</span>';
		updateCounts();
		return;
	}

	for (let token of tokens) {
		let result = await checkSingleToken(token);
		displayResult(token, result);
	}
}

async function checkSingleToken(token) {
	/*
	fetch @me object from discord:
	{
			"id": "",
			"username": "",
			"avatar": "",
			"discriminator": "",
			"public_flags": 256,
			"flags": 256,
			"email": null,
			"verified": false,
			"locale": "",
			"nsfw_allowed": true,
			"mfa_enabled": false,
			"phone": null
		}
	*/
	let response;
	try {
		response = await fetch("https://discordapp.com/api/v6/users/@me", {
			method: "GET",
			headers: { Authorization: token },
		});
		response = await response.json();
	} catch (e) {
		return { error: `Request failed: ${e}` };
	}

	/*
	if token is invalid => means if no username returned
	*/
	if (!response.username) {
		return { invalid: true };
	}

	/*
	if response.status !== 200 -> account is phoneblocked
	*/

	let phoneBlockCheck;
	try {
		phoneBlockCheck = await fetch("https://discordapp.com/api/v6/users/@me/library", {
			method: "GET",
			headers: { Authorization: token },
		});
		phoneBlockCheck = phoneBlockCheck.status;
	} catch (e) {
		return { error: `Request failed: ${e}` };
	}

	switch (phoneBlockCheck) {
		case 200:
			phoneBlockCheck = "not phone locked";
			break;
		default:
			phoneBlockCheck = "phone locked";
			break;
	}

	let result = {
		tag: response.username + "#" + response.discriminator,
		email: response.email || "no email",
		verified: response.verified ? "Email verified" : "Email not verified",
		id: response.id,
		locale: response.locale,
		phone: response.phone || "no phone number",
		phoneblocked: phoneBlockCheck,
		avatar: response.avatar ? "https://cdn.discordapp.com/avatars/" + response.id + "/" + response.avatar + ".png?size=256" : "https://cdn.discordapp.com/embed/avatars/" + (response.discriminator % 5) + ".png?size=256"
	};

	return result;
}

function displayResult(token, result) {
	var resultsDiv = document.getElementById("results");
	var tokenDiv = document.createElement("div");
	tokenDiv.className = "account-card";

	// status dot
	var statusDot = document.createElement('div');
	statusDot.className = 'status-dot ' + (result.invalid || result.error ? 'status-offline' : 'status-online');
	tokenDiv.appendChild(statusDot);

	if (result.error) {
		tokenDiv.dataset.status = 'invalid';
		tokenDiv.innerHTML += `
			<div class="account-top">
				<div class="account-info">
					<div class="account-username">${token}</div>
					<div class="account-sub">Request failed</div>
				</div>
			</div>
			<div class="badges">
				<span class="badge status">Error</span>
			</div>
			<span class="alert">${result.error}</span>
		`;
	} else if (result.invalid) {
		// show invalid card
		tokenDiv.dataset.status = 'invalid';
		tokenDiv.innerHTML += `
			<div class="account-top">
				<img class="account-avatar" src="https://cdn.discordapp.com/embed/avatars/0.png?size=256" />
				<div class="account-info">
					<div class="account-username">Invalid Token</div>
					<div class="account-sub">${token}</div>
				</div>
			</div>
			<div class="badges">
				<span class="badge status">Offline</span>
				<span class="badge">Invalid</span>
			</div>
		`;
	} else {
		// valid token card
		tokenDiv.dataset.status = 'valid';
		tokenDiv.innerHTML += `
			<div class="account-top">
				<img class="account-avatar" src="${result.avatar}" />
				<div class="account-info">
					<div class="account-username">${result.tag}</div>
					<div class="account-sub">${result.id}</div>
				</div>
			</div>
			<div class="badges">
				<span class="badge status">Online</span>
				<span class="badge valid">Valid</span>
			</div>
			<ul class="list_group">
				<li class="list_item"><strong>Token:</strong> ${token}</li>
				<li class="list_item"><strong>Email:</strong> ${result.email}</li>
				<li class="list_item"><strong>Verified:</strong> ${result.verified}</li>
				<li class="list_item"><strong>Locale:</strong> ${result.locale}</li>
				<li class="list_item"><strong>Phone:</strong> ${result.phone}</li>
			</ul>
			<div class="card-buttons">
				<button class="default_button" onclick="copySingleResult('${JSON.stringify(result).replace(/'/g, "\\'")}')">Copy</button>
				<button class="delete-btn" title="Remove">🗑️</button>
			</div>
		`;
	}

	resultsDiv.appendChild(tokenDiv);

	// attach delete handler
	var deleteBtn = tokenDiv.querySelector('.delete-btn');
	if (deleteBtn) {
		deleteBtn.addEventListener('click', function () {
			tokenDiv.remove();
			updateCounts();
		});
	}

	updateCounts();
} 

function updateCounts() {
	var valid = document.querySelectorAll('.account-card[data-status="valid"]').length;
	var invalid = document.querySelectorAll('.account-card[data-status="invalid"]').length;
	var validEl = document.getElementById('validCount');
	var invalidEl = document.getElementById('invalidCount');
	if (validEl) validEl.textContent = valid;
	if (invalidEl) invalidEl.textContent = invalid;
}

function copySingleResult(resultStr) {
	navigator.clipboard.writeText(resultStr);
}

function loadFile() {
	var fileInput = document.getElementById('fileInput');
	var file = fileInput.files[0];
	if (file) {
		var reader = new FileReader();
		reader.onload = function(e) {
			document.getElementById('tokenInput').value = e.target.result;
		};
		reader.readAsText(file);
	}
}
