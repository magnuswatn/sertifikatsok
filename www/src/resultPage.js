import React from 'react';
import { CertModal, RevokertModal, UnderenhetModal, UkjentModal, StringModal, PemModal } from './components/modals.js'
import { SertifikatsokCollapsible } from './components/collapsibles.js'
import { Loader } from './components/misc.js'
import { BregButton, LdapButton } from './components/buttons.js'
import { CertificateCard } from './components/cards.js'
import { RevokedNotice, UnderenhetNotice, UkjentNotice, WarningNotice } from './components/notices.js'
import { Badge, CALogo, getNorwegianDate, openBreg } from './misc.js'
import PropTypes from 'prop-types';
/* global fetch */
/* global window*/



const CertificateSet = (props) => {

    const badge = Badge(props.certificateSet.status);
    const logo = CALogo(props.certificateSet.issuer);

    const notices = [];
    if (props.certificateSet.status === 'Revokert') {
        notices.push(
            <RevokedNotice
                onClick={() => props.onClick('revoked')}
                key="revoked"
            />
        )
    }
    props.certificateSet.notices.forEach((notice) => {
        switch (notice) {
            case 'underenhet':
                notices.push(
                    <UnderenhetNotice
                        onClick={() => props.onClick('underenhet')}
                        key="underenhet"
                    />
                )
                break
            case 'ukjent':
                notices.push(
                    <UkjentNotice
                        onClick={() => props.onClick('ukjent')}
                        key="ukjent"
                    />
                )
                break
        }
    });

    return (
        <SertifikatsokCollapsible
            header={
                <div className="row">
                    <div className="col s3">Utstedt {getNorwegianDate(props.certificateSet.valid_from)}</div>
                    <div className="col s5">{props.certificateSet.subject}</div>
                    <div className="col s2">{badge}</div>
                    <div className="col s2">{logo}</div>
                </div>
            }
            body={
                <div>
                    {notices}
                    <h6 className="center-align">Dette settet er gyldig til {getNorwegianDate(props.certificateSet.valid_to)}</h6>
                    <br />
                    <div className="row">
                        {
                            props.certificateSet.certificates.map((certificate) => (
                                <div
                                    className="col s12 m6"
                                    key={certificate.info['Avtrykk (SHA-1)']}
                                >
                                    {CertificateCard(certificate, props.onClick)}
                                </div>
                            ))
                        }
                    </div>
                    <div>
                        <div className="divider"></div>
                        <br />
                        <div className="right-align">
                            {
                                props.certificateSet.org_number &&
                                <BregButton
                                    onClick={() => openBreg(props.certificateSet.org_number)}
                                />
                            }
                            &nbsp;
                            <LdapButton
                                onClick={() => props.onClick("string", props.certificateSet.ldap)}
                            />
                        </div>
                    </div>
                </div>
            }
        />
    )
}

const Warning = ({ errors }) => {
    return errors.map((error, i) => (
        <WarningNotice key={i} warningText={error} />)
    )
}

Warning.propTypes = {
    errors: PropTypes.array,
}

const callApi = async () => {
    const params = window.location.search
    let response;
    let result;
    try {
        response = await fetch(`/api?${params}`)
        result = await response.json();
    } catch (error) {
        return {
            success: false,
            errorMsg: "Fikk ikke kontakt med serveren. Vennligst prøv igjen senere.",
        }
    }

    if (response.ok) {
        return {
            success: true,
            result: result,
        }
    } else {
        return {
            success: false,
            errorMsg: result.error,
        }
    }
}

export class ResultPage extends React.Component {

    constructor(props) {
        super(props);
        this.state = {
            response: '',
            finishedLoading: false,
            modalOpen: false,
            errorMsg: null,
            modalId: '',
        };
    }

    async componentDidMount() {
        const result = await callApi();

        if (result.success) {
            this.setState({
                response: result.result,
                finishedLoading: true,
                success: true,
            });
        } else {
            this.setState({
                finishedLoading: true,
                success: false,
                errorMsg: result.errorMsg,
            });
        }
    }

    handleClick(type, hash) {
        if (type === 'cert') {
            window.history.replaceState(null, 'Sertifikatsøk', `#${hash}`);
            this.forceUpdate()
        } else {
            this.setState({
                modalOpen: true,
                modal: type,
                modalId: hash,
            });
        }
    }

    closeCertModal() {
        window.history.replaceState(null, 'Sertifikatsøk', `${window.location.search}`);
        this.forceUpdate()
    }

    testCloseModal() {
        this.setState({
            modalOpen: false,
            modal: '',
        });
    }

    showModal() {
        switch (this.state.modal) {
            case 'revoked':
                return (
                    <RevokertModal
                        remove={() => this.testCloseModal()}
                    />
                )
            case 'underenhet':
                return (
                    <UnderenhetModal
                        remove={() => this.testCloseModal()}
                    />
                )
            case 'ukjent':
                return (
                    <UkjentModal
                        remove={() => this.testCloseModal()}
                    />
                )
            case 'string':
                return (
                    <StringModal
                        remove={() => this.testCloseModal()}
                        string={this.state.modalId}
                    />
                )
            case 'pem':
                return (
                    <PemModal
                        remove={() => this.testCloseModal()}
                        cert={this.state.modalId}
                    />
                )
        }
    }

    render() {

        if (!(this.state.finishedLoading)) {
            return (
                <Loader />
            );
        } else if (!(this.state.success)) {
            return (
                <Warning errors={[this.state.errorMsg]} />
            )
        } else {
            return (
                <div>
                    <Warning errors={this.state.response.errors} />
                    <h5 className="center-align">Fant {this.state.response.certificate_sets.length} sett med sertifikater for {this.state.response.subject}:</h5>
                    <br />
                    {
                        this.state.response.certificate_sets.map((certSet) => (
                            <CertificateSet
                                key={certSet.certificates[0].info['Avtrykk (SHA-1)']}
                                certificateSet={certSet}
                                onClick={(type, hash) => this.handleClick(type, hash)}
                            />
                        ))
                    }
                    {this.showModal()}
                    <CertModal
                        remove={() => this.closeCertModal()}
                        certSets={this.state.response.certificate_sets}
                        onClick={(type, hash) => this.handleClick(type, hash)}
                    />
                </div>
            )
        }
    }
}
