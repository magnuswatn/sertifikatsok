let searchTimeout;
let lastQuery;
let certificates;

const handleWarnings = function(warnings) {
    if (warnings.length > 0) {
        const $warningRow = $('<div/>', {'class': 'row'});
        warnings.forEach(function(warning) {
            $warningRow.append('<div/>', {'class': 'col s6 offset-s3'}).append(
                $('<div/>', {'class': 'card-panel orange darken-4'}).append(
                    $('<span/>', {class: 'white-text', text: warning}).prepend(
                        $('<i/>', {class: 'material-icons', text: 'warning'})
                ))
            );
        });
        $warningRow.append('<br>');
        $('#body-container').append($warningRow);
    }
};

// Thanks to https://gist.github.com/fupslot/5015897
const base64toCertBlob = function(data, contentType) {
    const byteString = atob(data);

    const ab = new ArrayBuffer(byteString.length);
    let ia = new Uint8Array(ab);
    for (let i = 0; i < byteString.length; i++) {
        ia[i] = byteString.charCodeAt(i);
    }

    const bb = new Blob([ab], {type: 'application/pkix-cert'});
    return bb;
};

const handleFatalError = function(msg) {
    $('#body-container').empty();
    handleWarnings([msg]);
};

const getStatusBadge = function(certificateSet) {
    let color = 'green';
    switch (certificateSet.status) {
        case 'OK':
            color = 'green';
            break;
        case 'Revokert':
            color = 'red';
            break;
        case 'Ugyldig':
            color = 'red';
            break;
        case 'Utgått':
            color = 'grey';
            break;
        case 'Ukjent':
            color = 'grey';
            break;
    }
    return $('<span/>',
        {'class': `new badge ${color}`,
        'data-badge-caption': certificateSet.status});
};

const getNotificationMessage = function(certificateSet) {
    // TODO: We can only show one message at the time now
    // Should we support more?
    let $message = '';
    certificateSet.notices.forEach(function(notice) {
        switch (notice) {
            case 'underenhet':
               $message = $('#stashed-underenhet-notification').clone();
               break;
            case 'ukjent':
               $message = $('#stashed-ukjent-notification').clone();
               break;
        }
    });
    return $message;
};

const getNorwegianDate = (function() {
    const monthNames = [
      'januar', 'februar', 'mars',
      'april', 'mai', 'juni', 'juli',
      'august', 'september', 'oktober',
      'november', 'desember',
    ];

    return function(dateString) {
        const date = new Date(dateString);

        return `${date.getDate()}. ${monthNames[date.getMonth()]} `+
            `${date.getFullYear()}`;
    };
})();

 const updateCertModal = function($modal, certificate) {
    $modal.attr('id', certificate.info['Avtrykk (SHA-1)']);
    const values = ['Emne', 'Utsteder', 'Gyldig fra', 'Gyldig til',
                    'Serienummer (hex)', 'Serienummer (int)', 'Bruksområde(r)',
                    'Nøkkelbruk', 'Utvidet nøkkelbruk', 'Status', 'Type', 'Avtrykk (SHA-1)'];

    $table = $modal.find('tbody');
    values.forEach(function(value) {
        $row = $('<tr/>');
        $boldText = $('<b/>').text(value);
        $row.append($('<td/>').append($boldText));
        $row.append($('<td/>').text(certificate.info[value]));
        $table.append($row);
    });
    $('#modals').append($modal);
 };

const getCaIcon = function(certificateSet) {
    let image = '';
    switch (certificateSet.issuer) {
        case 'Buypass':
            image = 'resources/buypass.svg';
            break;
        case 'Commfides':
            image = 'resources/commfides.svg';
            break;
    }
    return $('<div/>', {class: 'right'})
        .append($('<img/>', {src: image}));
};

const showCertificateSets = function(certificateSets) {
    if (certificateSets.length > 0) {
        $ldapMessage = $('#stashed-ldap-string-box').clone();
        $certModal = $('#stashed-cert-modal').clone();

        certificateSets.forEach(function(certificateSet) {
            const $collapsibleLi = $('<li/>');
            const $collapsibleHeaderRow = $('<div/>', {class: 'row'});

            const norwegianFromDate = getNorwegianDate(
                certificateSet.valid_from);
            $collapsibleHeaderRow.append($('<div/>', {class: 'col s3'})
                .text(`Utstedt ${norwegianFromDate}`));
            $collapsibleHeaderRow.append($('<div/>', {class: 'col s5'})
                .text(certificateSet.subject));

            const statusBadge = getStatusBadge(certificateSet);
            $collapsibleHeaderRow.append($('<div/>', {class: 'col s2'})
            .append(statusBadge));

            const CaImage = getCaIcon(certificateSet);
            $collapsibleHeaderRow.append($('<div/>', {class: 'col s2'})
                .append(CaImage));

            const $collapsibleHeader = $('<div/>',
                {class: 'collapsible-header'}).append($collapsibleHeaderRow);
            $collapsibleLi.append($collapsibleHeader);

            const $collapsibleBodySpan = $('<span/>');
            if (certificateSet.status === 'Revokert') {
                $collapsibleBodySpan.append($('#stashed-revoked-notification')
                    .clone());
            }

            $collapsibleBodySpan.append(getNotificationMessage(certificateSet));

            const norwegianToDate = getNorwegianDate(certificateSet.valid_to);
            const certificateSetIntro = `Dette settet er gyldig til `+
                `${norwegianToDate}`;

            $collapsibleBodySpan.append($('<h6/>', {class: 'center-align'})
                .text(certificateSetIntro));

            $collapsibleBodySpan.append('<br>');

            const $certificateRow = $('<div/>', {class: 'row'});

            certificateSet.certificates.forEach(function(certificate) {
                const $certificateEntry = $('<div/>',
                    {class: 'card-content white-text'});
                $certificateEntry.append($('<span/>',
                    {class: 'card-title'}).text(certificate.name));

                const $certificateInfo = $('<p/>');
                const values = ['Bruksområde(r)', 'Serienummer (hex)',
                                'Serienummer (int)', 'Avtrykk (SHA-1)'];
                values.forEach(function(value) {
                    $certificateInfo.append($('<div/>', {class: 'left'})
                        .text(value));
                    $certificateInfo.append($('<div/>', {class: 'right'})
                        .text(certificate.info[value]));
                    $certificateInfo.append('<br>');
                });
                $certificateEntry.append($certificateInfo);

                const $fullCertificateEntry = $('<div/>', {class: 'col s12 m6'})
                    .append($('<div/>',
                            {class: 'card blue-grey darken-1 hoverable cert'})
                                .append($certificateEntry));

                certBlob = base64toCertBlob(certificate.certificate);
                certificates[certificate.info['Avtrykk (SHA-1)']] = certBlob;

                const $certificateEntryLink = $('<a/>',
                    {href: `#${certificate.info['Avtrykk (SHA-1)']}`, id: 'certCard'})
                    .append($fullCertificateEntry);

                    $certificateRow.append($certificateEntryLink);

                const $thisCertModal = $certModal.clone();
                updateCertModal($thisCertModal, certificate);
            });
            $collapsibleBodySpan.append($certificateRow);

            const $thisLdapMessage = $ldapMessage.clone();
            $thisLdapMessage.find('.ldap-button')
                .attr('ldap', certificateSet.ldap);
            $collapsibleBodySpan.append($thisLdapMessage);

            $brregButton = $thisLdapMessage.find('.brreg-button');

            if (certificateSet.org_number) {
                $brregButton.attr('orgnr', certificateSet.org_number);
            } else {
                $brregButton.remove();
            }

            const $collapsibleBody = $('<div/>', {class: 'collapsible-body'})
                .append($collapsibleBodySpan);

            $collapsibleLi.append($collapsibleBody);

            const $collapsible = $('<ul/>',
                {'class': 'collapsible', 'data-collapsible': 'expandable'})
                .append($collapsibleLi);

            $('#body-container').append($collapsible);
        });
    }
};

const loadMaterialize = function() {
    // Since we dynamically load these, we need to activate them
    $('.collapsible').collapsible();
    $('.tooltipped').tooltip({delay: 50});
    $('.modal').modal({
        complete: function() {
            // We must not change the hash when the string modal closes
            // as it is used on top of another modal
            if ($(this).attr('id') !== 'string-modal' ) {
	         history.replaceState(null, 'Sertifikatsøk', '#!');
            }
        },
      }
    );
};

const loadLoader = function() {
    $('#body-container').empty();
    const $loader = $('#stashed-loader').clone();
    $('#body-container').append($loader);
};

const loadSearchGUI = function() {
    $('#body-container').empty();
    const $searchPage = $('#stashed-searchpage').clone();
    $('#body-container').append($searchPage);
    // Activate the tabs
    $('ul.tabs').tabs();
};

const loadResultGUI = function(response) {
    $('#body-container').empty();
    handleWarnings(response.errors);

    const env = window.location.search.includes('test') ? ' i test' : '';

    $amountMessage = $('<h5/>', {'class': 'center-align'});
    $amountMessage.text(`Fant ${response.certificate_sets.length} `+
                        `sett med sertifikater for ${response.subject}`+
                        `${env}:`);
    $('#body-container').append($amountMessage);
    $('#body-container').append('<br>');

    showCertificateSets(response.certificate_sets);
    loadMaterialize();
    if (window.location.hash !== '#!') {
        $(window.location.hash).modal('open');
    }
};

const getResponse = async function(query) {
    certificates = {};
    loadLoader();
    let response;
    try {
        response = await $.getJSON(`/api${query}`);
    } catch (error) {
        if (error.responseJSON) {
            handleFatalError(error.responseJSON.error);
        } else {
            handleFatalError('Fikk ikke kontakt med serveren. '+
                             'Vennligst prøv igjen senere.');
        };
        return false;
    }
    loadResultGUI(response);
};

// credit to: https://stackoverflow.com/questions/985272/
 const selectText = function(element) {
        const text = document.getElementById(element);

        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(text);
        selection.removeAllRanges();
        selection.addRange(range);
 };

const loadPage = function() {
    if (window.location.search !== '') {
        // Result view
        if (window.location.search !== lastQuery) {
            lastQuery = window.location.search;
            getResponse(window.location.search);
        } else if (window.location.hash !== '#!') {
            const lowerHash = window.location.hash.toLowerCase();
            $(lowerHash).modal('open');
        } else if (window.location.hash === '#!') {
            $('.modal').modal('close');
        }
    } else {
        // Search view
        if ($('.modal').hasClass('open')) {
            $('.modal').modal('close');
        }
        lastQuery = '';
        loadSearchGUI();
        $('#enterprise-search-value').focus();
    }
};

const search = function(env) {
    let type;
    let inputValue;
    if ($('#enterprise-search').attr('class')) {
        type = 'enterprise';
        $inputForm = $('#enterprise-search-value');
        // If the input have a nine-digit number in parentheses,
        // we assume it's from autocomplete, and search for the number only
        const re = /\((\d{9})\)/;
        reResult = re.exec($inputForm.val());
        if (reResult) {
            inputValue = reResult[1];
        } else {
            inputValue = $inputForm.val();
        }
    } else {
        type = 'person';
        $inputForm = $('#person-search-value');
        inputValue = $inputForm.val();
    }
    if ($inputForm.val() === '') {
        $inputForm.addClass('invalid');
        return false;
    }
    const queryParams = [
        {name: 'query', value: inputValue.trim()},
        {name: 'env', value: env},
        {name: 'type', value: type},
    ];
    history.pushState(null, 'Resultat', `/?${$.param(queryParams)}`);
    loadPage();
};

const downloadCert = function(hash) {
    const blob = certificates[hash];
    const fileName = `${hash}.cer`;
    if (window.navigator.msSaveBlob) {
        // In case of EDGE cases
        // hahahahaha, I'm so funny
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

const showPEM = function(hash) {
    // thanks https://stackoverflow.com/questions/18650168/convert-blob-to-base64
    const blob = certificates[hash];
    const fileReader = new window.FileReader();
    fileReader.readAsDataURL(blob);
    fileReader.onloadend = function(hash) {
        b64cert = (fileReader.result)
            .substr((fileReader.result)
            .indexOf(',')+1);

        // Homemade PEM is the best PEM
        let pem = '-----BEGIN CERTIFICATE-----<br>';
        for (let i = 1; i<=b64cert.length; i++) {
            let char = b64cert.charAt(i-1);
            if (i % 64 === 0) {
                pem += `${char}<br>`;
            } else {
                pem += char;
            }
        }
        if (pem.slice(-1) !== '>') {
            pem += '<br>';
        }
        pem += '-----END CERTIFICATE-----';

          $('#string-modal').modal('open');
          // Should be OK to use html here, as the input is PEM encoded by us
          $('#string-modal-string').html(`<p class="pem">${pem}</p>`);
          selectText('string-modal-string');
    };
};

$(document.body).on('click', '.ldap-button', function(e) {
    $('#string-modal').modal('open');
    $('#string-modal-string').text($(this).attr('ldap'));
    selectText('string-modal-string');
});

$(document.body).on('click', '.brreg-button', function(e) {
    const orgNumber = $(this).attr('orgnr');
    window.open(`https://w2.brreg.no/enhet/sok/detalj.jsp?orgnr=${orgNumber}`);
});

$(document.body).on('click', '.download-button', function(e) {
    hash = $(this).parent().parent().parent().attr('id');
    downloadCert(hash);
});

$(document.body).on('click', '.pem-button', function(e) {
    hash = $(this).parent().parent().parent().attr('id');
    showPEM(hash);
});

$(document.body).on('click', '.revokert', function() {
    $('#revokert-modal').modal('open');
    return false;
});

$(document.body).on('click', '.underenhet', function() {
    $('#underenhet-modal').modal('open');
    return false;
});

// Not change the hash when the close button on the string modal is pressed
// as it is used in front of another modal
$(document.body).on('click', '#string-modal-close', function() {
    return false;
});

$(document.body).on('click', '.ukjent', function() {
    $('#ukjent-modal').modal('open');
    return false;
});

$(document.body).on('click', '#hjelp-button', function() {
    $('#hjelp-modal').modal();
    $('#hjelp-modal').modal('open');
    return false;
});

$(document.body).on('click', '#logo', function() {
    history.pushState(null, 'Sertifikatsøk', '/');
    loadPage();
    return false;
});

$(document.body).on('click', '#search-button', function() {
    search('prod');
});

$(document.body).on('click', '#search-test-button', function() {
    search('test');
});

$(document.body).on('click', '#certCard', function(e) {
    history.replaceState(null, 'Sertifikatsøk', e.currentTarget.href);
    loadPage();
    return false;
});


// The string modal is used on top of another modal,
// so we need to make sure only that is closed when pressing ESC
// and not the underlying modal
$(document.body).on('keydown', function(key) {
    if (key.which === 27) {
        if ($('#string-modal').hasClass('open')) {
            $('#string-modal').modal('close');
            return false;
        }
    };
});

$(document.body).on('keyup', '.search-box', function(key) {
    $(this).removeClass('invalid');
    if (key.which === 13) {
        search('prod');
    }
});

$(document.body).on('click', '#enterprise-search', function() {
    $('#enterprise-search-value').focus();
});

$(document.body).on('click', '#person-search', function() {
    $('#person-search-value').focus();
});

$(window).on('popstate', function(e) {
    loadPage();
});

// Autocomplete from Brønnøysundregistrene when searching after enterprises
$(document.body).on('keyup', '#enterprise-search-value', async function() {
    const $field = $(this);

    if (searchTimeout) {
        window.clearTimeout(searchTimeout);
    }
    searchTimeout = window.setTimeout(async function() {
        const searchValue = $field.val().split('\'').join('');
        if (searchValue.length > 3) {
            const companies = await getCompanies(searchValue);
            $field.autocomplete({
                data: companies,
                limit: 20,
            });
            $field.focus();
        };
    }, 500);
});

const getCompanies = async function(startOfName) {
    const url='https://data.brreg.no/enhetsregisteret/enhet.json';
    const filter={
        $filter: `startswith(navn,'${startOfName}')`,
    };
    const response = await $.getJSON(url, filter);

    companies = {};
    if (response.data) {
        for (let i=0, len=response.data.length; i<len; i++) {
            companies[`${response.data[i].navn} `+
                      `(${response.data[i].organisasjonsnummer})`] = null;
        }
    };
    return companies;
};

$(function() {
    loadPage();
});
