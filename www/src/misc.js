import React from 'react';
/* global window */
/* global document */
/* global atob */
/* global Blob */
/* global ArrayBuffer */
/* global Uint8Array */

export const CALogo = (issuer) => {
    let image = '';
    switch (issuer) {
        case 'Buypass':
            image = 'buypass.svg';
            break;
        case 'Commfides':
            image = 'commfides.svg';
            break;
    }

    return (
        <div className="right">
            <img alt={`${issuer}-logo`} src={image} />
        </div>
    )
}

export const Badge = (status) => {
    let color = 'grey';
    switch (status) {
        case 'OK':
            color = 'green';
            break;
        case 'Revokert':
            color = 'red';
            break;
        case 'Ugyldig':
            color = 'red';
            break;
    }
    return (
        <span className={"new badge " + color} data-badge-caption={status}></span>
    )
}

export const getNorwegianDate = (function () {
    const monthNames = [
        'januar', 'februar', 'mars',
        'april', 'mai', 'juni', 'juli',
        'august', 'september', 'oktober',
        'november', 'desember',
    ];

    return function (dateString) {
        const date = new Date(dateString);

        return `${date.getDate()}. ${monthNames[date.getMonth()]} ` +
            `${date.getFullYear()}`;
    };
})();


export const showPEM = (b64cert) => {
    // Homemade PEM is the best PEM
    let pem = `-----BEGIN CERTIFICATE-----\n`;
    for (let i = 1; i <= b64cert.length; i++) {
        let char = b64cert.charAt(i - 1);
        if (i % 64 === 0) {
            pem += `${char}\n`;
        } else {
            pem += char;
        }
    }
    if (pem.slice(-1) !== '>') {
        pem += '\n';
    }
    pem += '-----END CERTIFICATE-----';
    return pem
};

// Thanks to https://gist.github.com/fupslot/5015897
const base64toCertBlob = (data) => {
    const byteString = atob(data);

    const ab = new ArrayBuffer(byteString.length);
    let ia = new Uint8Array(ab);
    for (let i = 0; i < byteString.length; i++) {
        ia[i] = byteString.charCodeAt(i);
    }

    const bb = new Blob([ab], { type: 'application/pkix-cert' });
    return bb;
};

export const downloadCert = (b64cert, hash) => {

    const blob = base64toCertBlob(b64cert)
    const fileName = `${hash}.cer`;
    if (window.navigator.msSaveBlob) {
        // In case of edge cases
        // (I'm very funny)
        window.navigator.msSaveBlob(blob, fileName);
    } else {
        const a = document.createElement('a');
        a.style = 'display: none';
        const url = window.URL.createObjectURL(blob);
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();

        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }
};

// credit to: https://stackoverflow.com/questions/985272/
export const selectText = (element) => {
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(element);
    selection.removeAllRanges();
    selection.addRange(range);
};

export const openBreg = (orgnr) => {
    window.open(`https://w2.brreg.no/enhet/sok/detalj.jsp?orgnr=${orgnr}`);
}
