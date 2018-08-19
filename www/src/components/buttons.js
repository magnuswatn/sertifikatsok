import React, { Component } from 'react';
import PropTypes from 'prop-types';
import M from 'materialize-css';

export class SertifikatsokButton extends Component {
    constructor(props) {
        super(props);
        this.ref = React.createRef();
    }

    handleHover() {
        this.self = M.Tooltip.init(this.ref.current)
    }

    handleHoverAway() {
        this.self.destroy();
    }

    render() {
        return (
            <a ref={this.ref} onClick={this.props.onClick} onMouseEnter={() => this.handleHover()} onMouseLeave={() => this.handleHoverAway()} className="btn-floating btn waves-effect waves-light red tooltipped hoverable" data-position={this.props.position} data-tooltip={this.props.hoverText} tabIndex="0">
                {this.props.text}
            </a>
        )
    }
}

SertifikatsokButton.propTypes = {
    hoverText: PropTypes.string,
    position: PropTypes.string,
    onClick: PropTypes.func,
    text: PropTypes.oneOfType([
        PropTypes.object,
        PropTypes.string,
    ])
}


export const SertifikatsokButtonWithIcon = (props) => (
    <SertifikatsokButton
        text={<i className="material-icons">{props.icon}</i>}
        {...props}
    />
)

SertifikatsokButtonWithIcon.propTypes = {
    icon: PropTypes.string,
}

export const BregButton = (props) => (
    <SertifikatsokButtonWithIcon
        icon="business"
        position="top"
        hoverText="Slå opp bedriften i Brønnøysundregistrene"
        {...props}
    />
)

export const LdapButton = (props) => (
    <SertifikatsokButtonWithIcon
        icon="link"
        position="top"
        hoverText="Se LDAP-streng for dette settet"
        {...props}
    />
)

export const SertifikatsokSearchbutton = (props) => (
    <button className="btn waves-effect waves-light valign-wrapper" onClick={props.onClick}>{props.text}</button>
)

SertifikatsokSearchbutton.propTypes = {
    text: PropTypes.string,
    onClick: PropTypes.func,
}
