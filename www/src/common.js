import React from 'react';
import { SertifikatsokButton } from './components/buttons.js';
import PropTypes from 'prop-types';

export const Header = () => (
    <header className="App-header">
        <div className="container">
            <div className="center">
                <div className="row">
                    <a href="/">
                        <div className="col s12 m4 offset-m4 offset-s0" id="logo">
                            <div className="card-panel grey">
                                <span className="white-text">
                                    <h5>Sertifikatsøk</h5>
                                    <h6 className="center-align header">Søk etter norske kvalifiserte sertifikater</h6>
                                </span>
                            </div>
                        </div>
                    </a>
                </div>
            </div>
        </div>
    </header>
);


export const Footer = () => (
    <footer className="page-footer white">
        <div className="center-align">
            <a href="https://github.com/magnuswatn/sertifikatsok">
                <img alt="Github-logo" src="github.svg" height="32" />
            </a>
        </div>
    </footer>
);

export const HelpButton = ({ onClick }) => (
    <div className="fixed-action-btn">
        <SertifikatsokButton
            text="?"
            position="left"
            hoverText="Litt forklaring"
            onClick={() => onClick()}
        />
    </div>
)

HelpButton.propTypes = {
    onClick: PropTypes.func,
}
