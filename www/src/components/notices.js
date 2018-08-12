import React from 'react';
import PropTypes from 'prop-types';

const handleKeyPress = (e, callback) => {
    if (e.key === 'Enter') {
        callback();
    }
}

const SertifikatsokNotice = ({ color, textColor, icon, text, onClick, hoverable = true }) => (
    <div className="row">
        <div className="col s12">
            <div
                className={"card-panel " + (hoverable ? "hoverable " : "") + color}
                onClick={onClick}
                onKeyPress={(e) => (handleKeyPress(e, onClick))}
                tabIndex={hoverable ? "0" : "-1"}
            >
                <span className={textColor}>
                    <i className="material-icons">{icon}</i>
                    {text}
                </span>
            </div>
        </div>
    </div >
)

SertifikatsokNotice.propTypes = {
    color: PropTypes.string,
    textColor: PropTypes.string,
    icon: PropTypes.string,
    text: PropTypes.string,
    onClick: PropTypes.func,
    hoverable: PropTypes.bool,
}


export const RevokedNotice = ({ onClick }) => (
    <SertifikatsokNotice color="orange"
        textColor="white-text"
        icon="warning"
        text="Disse sertifikatene er revokerte og dermed ikke gyldige"
        onClick={onClick}
    />
)

RevokedNotice.propTypes = {
    onClick: PropTypes.func,
}

export const UnderenhetNotice = ({ onClick }) => (
    <SertifikatsokNotice color="grey lighten-4"
        textColor="black-text"
        icon="info"
        text="Disse sertifikatene er utstedt til en underenhet. Trykk her for å lese mer."
        onClick={onClick}
    />
)

UnderenhetNotice.propTypes = {
    onClick: PropTypes.func,
}

export const UkjentNotice = ({ onClick }) => (
    <SertifikatsokNotice color="grey lighten-4"
        textColor="black-text"
        icon="info"
        text="Disse sertifikatene er av en ukjent type. Trykk her for å lese mer."
        onClick={onClick}
    />
)

UkjentNotice.propTypes = {
    onClick: PropTypes.func,
}

export const WarningNotice = ({ warningText }) => (
    <SertifikatsokNotice color="orange darken-4"
        textColor="white-text"
        icon="warning"
        text={warningText}
        hoverable={false}
    />
)

WarningNotice.propTypes = {
    warningText: PropTypes.string,
}
