import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { SertifikatsokButtonWithIcon } from './buttons.js';
import { showPEM, downloadCert, selectText } from '../misc.js'
import M from 'materialize-css';
/* global window*/

export class SertifikatsokModal extends Component {
    constructor(props) {
        super(props);
        this.ref = React.createRef();
        this.modal = null;
    }

    componentDidMount() {
        this.modal = M.Modal.init(this.ref.current, { onCloseEnd: this.props.remove, inDuration: 150, outDuration: 150 });
        this.modal.open();

        if (this.props.markText) {
            selectText(this.ref.current);
        }
    }

    render() {
        return (
            <div ref={this.ref} className={"modal " + this.props.extraClass}>
                <div className="modal-content">
                    <div className="right">
                        <a className="modal-action modal-close waves-effect waves-green btn-flat modal-close-button"><i className="material-icons">close</i></a>
                    </div>
                    <h4>{this.props.header}</h4>
                    {this.props.body}
                </div>
            </div>
        )
    }
}

SertifikatsokModal.propTypes = {
    remove: PropTypes.func,
    header: PropTypes.string,
    extraClass: PropTypes.string,
    markText: PropTypes.bool,
    body: PropTypes.oneOfType([
        PropTypes.object,
        PropTypes.string,
    ]),
}

export const CertModal = ({ remove, certSets, onClick }) => {

    const values = ['Emne', 'Utsteder', 'Gyldig fra', 'Gyldig til',
        'Serienummer (hex)', 'Serienummer (int)', 'Bruksområde(r)',
        'Nøkkelbruk', 'Status', 'Type', 'Avtrykk (SHA-1)'];

    const certHash = window.location.hash.substring(1)

    if (!(certHash)) {
        return null
    }

    let theCert;

    certSets.forEach((certSet) => {
        certSet.certificates.forEach((cert) => {
            if (cert.info["Avtrykk (SHA-1)"] === certHash) {
                theCert = cert;
            }
        }
        )
    })

    if (!(theCert)) {
        return null
    }

    return (
        <SertifikatsokModal
            extraClass="cert-modal"
            remove={remove}
            header="Sertifikat"
            body={
                <div>
                    <table className="bordered">
                        <thead>
                            <tr>
                                <th />
                                <th />
                            </tr>
                        </thead>
                        <tbody>
                            {
                                values.map((value) => (
                                    <tr key={value}>
                                        <td>
                                            <b>{value}</b>
                                        </td>
                                        <td>{theCert.info[value]}</td>
                                    </tr>
                                ))
                            }
                        </tbody>
                    </table>
                    <br />
                    <div className="modal-footer">
                        <SertifikatsokButtonWithIcon
                            hoverText="Vis PEM"
                            position="top"
                            icon="content_copy"
                            onClick={() => { onClick("pem", theCert.certificate) }}
                        />
                        &nbsp;
                    <SertifikatsokButtonWithIcon
                            hoverText="Last ned dette sertifikatet"
                            position="top"
                            icon="file_download"
                            onClick={() => { downloadCert(theCert.certificate, certHash) }}
                        />
                    </div>
                </div>
            }
        />
    )
}

CertModal.propTypes = {
    remove: PropTypes.func,
    certSets: PropTypes.array,
    onClick: PropTypes.func,
}

export const HjelpModal = ({ remove, open }) => {
    if (!(open)) {
        return null
    } else {
        return (
            <SertifikatsokModal
                header="Norske kvalifiserte sertifikater"
                body={
                    <div>
                        Norske kvalifiserte sertifikater er digitale ID-papirer, som kan brukes til å bekrefte identitet i den digitale verdenen. De baserer seg på samme teknologi som f.eks. SSL-sertifikater, og er spesifisert i <a href="https://www.regjeringen.no/no/dokumenter/kravspesifikasjon-for-pki-i-offentlig-se/id611085/">Kravspesifikasjon for PKI i offentlig sektor</a>.
                        <br />
                        <p>Det finnes i praksis to typer norske kvalifiserte sertifikater:</p>
                        <h5>Person-sertifikater</h5>
                        Person-sertifikater representerer en norsk statsborger i folkeregisteret. Slike sertifikater brukes typisk til:
                            <ul className="browser-default">
                            <li>Innlogging på tjenester som krever høy sikkerhet.</li>
                            <li>Signering av f.eks. avtaler eller e-resepter</li>
                            <li>Signering og kryptering av e-poster (S/MIME)</li>
                        </ul>
                        Person-sertifikater utstedes kun i fysisk form, da enten et smartkort (&quot;tippekort&quot;) eller en USB-pinne.
                            <br /><br />
                        <h5>Virksomhetssertifikater</h5>
                        Virksomhetssertifikater identifiserer en virksomhet registrert i Brønnøysundregistrene. Brukes typisk til:
                            <ul className="browser-default">
                            <li>Autentisering av virksomheten i maskin-til-maskin-kommunikasjon (f.eks. mellom fagsystemer i helsesektoren)</li>
                            <li>Signering av dokumenter på vegne av virksomheten</li>
                        </ul>
                        Virksomhetssertifikater er typisk &quot;soft-sertifikater&quot;, men de finnes også i fysisk variant, da i form av smartkort.
                            <br /><br />
                        <p>Det er i praksis to utstedere av kvalifiserte sertifikater Norge i dag, <a href="https://www.buypass.no">Buypass</a> og <a href="https://www.commfides.com/">Commfides</a>.</p>
                    </div>
                }
                remove={remove}
            />
        )
    }
}


export const UnderenhetModal = ({ remove }) => (
    <SertifikatsokModal
        header="Sertifikater utstedt til underenhet"
        body={
            <div>Disse sertifikatene er utstedt til en underenhet av denne organisasjonen. Slike sertifikater har organisasjonsnummeret til hovedenheten i &quot;serialNumber&quot;-feltet og organisasjonsnummeret til underenheten i &quot;OU&quot;-feltet.
            <br /><br />
                Eksempel:
        <div className="row">
                    <div className="col s12 m5">
                        <div className="card-panel teal">
                            <span className="white-text">
                                serialNumber = 995546973
                            <br />
                                O = WATN IT SYSTEM
                            <br />
                                OU = WATN UNDERENHET-113328475
                        </span>
                        </div>
                    </div>
                </div>
                Vær obs på at slike sertifikater kan bli tolket forskjellig fra system til system. Noen vil tolke det som at det tilhører underenheten, mens andre vil tolke det som tilhørende hovedenheten.</div>
        }
        remove={remove}
    />
)

UnderenhetModal.propTypes = {
    remove: PropTypes.func,
}

export const RevokertModal = ({ remove }) => (
    <SertifikatsokModal
        header="Revokerte sertifikater"
        body="Revokerte sertifikater er tilbaketrukket fra sertifikatutstederen. Det kan være pga. informasjonen i sertifikatet ikke lenger er gyldig (f.eks. selskap avviklet), eller at den private nøkkelen har kommet på avveie. Slike sertifikater må ikke stoles på eller brukes."
        remove={remove}
    />
)

RevokertModal.propTypes = {
    remove: PropTypes.func,
}

export const UkjentModal = ({ remove }) => (
    <SertifikatsokModal
        header="Ukjent sertifikattype"
        body="Alle norske kvalifiserte sertifikater skal ha en en kode i seg (Policy OID) som beskriver hvilken type sertifikat det er. Disse sertifikatene hadde en ukjent kode i seg, som tyder på at det ikke er et vanlig sertifikat. Bør kun stoles på eller brukes i spesielle tilfeller."
        remove={remove}
    />
)

UkjentModal.propTypes = {
    remove: PropTypes.func,
}

export const StringModal = ({ remove, string }) => (
    <SertifikatsokModal
        body={string}
        remove={remove}
        markText={true}
    />
)

StringModal.propTypes = {
    remove: PropTypes.func,
    string: PropTypes.string,
}

export const PemModal = ({ remove, cert }) => {

    return (
        <SertifikatsokModal
            body={
                <div className="pem">
                    {showPEM(cert)}
                </div>
            }
            remove={remove}
            markText={true}
        />
    )
}

PemModal.propTypes = {
    remove: PropTypes.func,
    cert: PropTypes.string,
}
