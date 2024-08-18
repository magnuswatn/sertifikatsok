export const getNorwegianDate = (function () {
    const monthNames = [
        "januar",
        "februar",
        "mars",
        "april",
        "mai",
        "juni",
        "juli",
        "august",
        "september",
        "oktober",
        "november",
        "desember",
    ];

    return function (dateString, includeTime = false) {
        const date = new Date(dateString);

        let norwegianDate =
            `${date.getDate()}. ${monthNames[date.getMonth()]} ` +
            `${date.getFullYear()}`;
        if (includeTime) {
            let hours = `${date.getHours()}`.padStart(2, "0");
            let minutes = `${date.getMinutes()}`.padStart(2, "0");
            norwegianDate += ` kl. ${hours}:${minutes}`;
        }
        return norwegianDate;
    };
})();

export const downloadCert = function (base64cert, thumbprint) {
    const byteString = window.atob(base64cert);

    const fileName = `${thumbprint}.cer`;

    const ab = new ArrayBuffer(byteString.length);
    let ia = new Uint8Array(ab);
    for (let i = 0; i < byteString.length; i++) {
        ia[i] = byteString.charCodeAt(i);
    }

    const blob = new Blob([ab], { type: "application/pkix-cert" });

    const a = document.createElement("a");
    const url = window.URL.createObjectURL(blob);
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();

    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
};

export const getPemFromBase64 = (base64cert) => {

    // Homemade PEM is the best PEM
    let pem = "-----BEGIN CERTIFICATE-----\n";
    for (let i = 1; i <= base64cert.length; i++) {
        let char = base64cert.charAt(i - 1);
        if (i % 64 === 0) {
            pem += `${char}\n`;
        } else {
            pem += char;
        }
    }
    if (pem.slice(-1) !== "\n") {
        pem += "\n";
    }
    pem += "-----END CERTIFICATE-----";
    return pem;
};

export const getCompanies = async function (startOfName) {

    const queryParams = new URLSearchParams([
        ["navn", startOfName],
    ]);
    const url = `https://data.brreg.no/enhetsregisteret/api/enheter?${queryParams}`;

    const response = await (await fetch(url)).json();

    const companies = {};
    if (response._embedded && response._embedded.enheter) {
        for (let i = 0, len = response._embedded.enheter.length; i < len; i++) {
            companies[`${response._embedded.enheter[i].navn} ` +
                `(${response._embedded.enheter[i].organisasjonsnummer})`] = null;
        }
    };
    return companies;
};

export const isBrregSearchable = function (query) {
    if (query.length < 4 || query.startsWith("ldap://") || query.startsWith("NTRNO-")) {
        return false;
    }

    // Only numeric is normally org numbers or serial numbers
    // and hex are thumbprints or serial numbers.
    const onlyNumericRegex = /^\d+$/;
    const hexSerialRegex = /(?:[0-9a-fA-F][\s:]?){16,}/;
    if (onlyNumericRegex.exec(query) || hexSerialRegex.exec(query)) {
        return false;
    }

    return true;
}

export const getStatusBadgeColor = function (status) {
    let color = "green";
    switch (status) {
        case "OK":
            color = "green";
            break;
        case "Revokert":
            color = "red";
            break;
        case "Ugyldig":
            color = "red";
            break;
        case "Utgått":
            color = "grey";
            break;
        case "Ukjent":
            color = "grey";
            break;
    }
    return color;
};

export const selectText = function (element) {

    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(element);
    selection.removeAllRanges();
    selection.addRange(range);
};

export const getEnterpriseSearchValue = function (text) {
    // If the input have a nine-digit number in parentheses,
    // we assume it's from autocomplete, and search for the number only
    const re = /\((\d{9})\)/;
    let reResult = re.exec(text);
    if (reResult) {
        return reResult[1];
    }
    return text;
}

class ApiError extends Error {
    constructor(error_text, ...params) {
        super(...params);

        this.error_text = error_text;
    }
}

const getVersion = () => {
    let versionElem = document.querySelector("meta[name='version']");
    if (versionElem instanceof HTMLMetaElement) {
        return versionElem.content;
    }
    return 'dev';
}

export const callApi = async function (query) {
    let response = await fetch(`/api${query}`,
        {
            "headers": { "sertifikatsok-version": getVersion() }
        });

    let jsonResponse = await response.json();
    if (response.status == 200) {
        return jsonResponse;
    }
    throw new ApiError(jsonResponse.error);
}

export const callRevocationInfoApi = async function (query, base64cert) {

    const byteString = window.atob(base64cert);

    const ab = new ArrayBuffer(byteString.length);
    let ia = new Uint8Array(ab);
    for (let i = 0; i < byteString.length; i++) {
        ia[i] = byteString.charCodeAt(i);
    }

    let response = await fetch(`/revocation_info${query}`, {
        method: "POST",
        headers: {
            "sertifikatsok-version": getVersion(),
            "content-type": "application/pkix-cert"
        },
        body: ia
    });

    let jsonResponse = await response.json();
    if (response.status == 200) {
        return jsonResponse;
    }
    throw new ApiError(jsonResponse.error);
};

export const getErrorText = function (error) {
    if (error instanceof ApiError) {
        return error.error_text;
    }
    return "Fikk ikke kontakt med serveren. Vennligst prøv igjen senere";
}
