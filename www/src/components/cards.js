import React from 'react';
import PropTypes from 'prop-types';

export const SertifikatsokCard = ({ title, body, onClick }) => (
    <div className="card blue-grey darken-1 hoverable" tabIndex="0" style={{ cursor: 'pointer' }} onClick={onClick}>
        <div className="card-content white-text">
            <span className="card-title">{title}</span>
            {body}
        </div>
    </div>
)

SertifikatsokCard.propTypes = {
    title: PropTypes.string,
    body: PropTypes.array,
    onClick: PropTypes.func,
}

export const CertificateCard = (certificate, onClick) => {

    const values = ['Bruksområde(r)', 'Serienummer (hex)',
        'Serienummer (int)', 'Avtrykk (SHA-1)'];

    const hash = certificate.info['Avtrykk (SHA-1)'];

    return (
        <SertifikatsokCard
            title={certificate.name}
            onClick={() => onClick('cert', hash)}
            body={
                values.map((value) => (
                    <div key={value}>
                        <div className="left">{value}</div>
                        <div className="right">{certificate.info[value]}</div>
                        <br />
                    </div>
                ))
            }
        />
    )
}
