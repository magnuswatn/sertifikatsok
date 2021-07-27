// Internet Explorer can't parse the main JS file,
// so this needs to be in a separate file

var showError = function (msg) {
    $('#body-container').empty();
    var $warningRow = $('<div/>', { 'class': 'row' });
    $warningRow.append('<div/>', { 'class': 'col s6 offset-s3' }).append(
        $('<div/>', { 'class': 'card-panel orange darken-4' }).append(
            $('<span/>', { class: 'white-text', text: msg }).prepend(
                $('<i/>', { class: 'material-icons', text: 'warning' })
            ))
    );
    $('#body-container').append($warningRow);
};


$(function () {
    if (navigator.userAgent.indexOf('Trident') !== -1) {
        showError('Internet Explorer er dessverre ikke støttet. Prøv med en moderne nettleser.');
    };
});
