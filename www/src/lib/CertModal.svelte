<script>
    import { createEventDispatcher, onMount } from "svelte";
    import DownloadCertButton from "./buttons/DownloadCertButton.svelte";
    import PemButton from "./buttons/PemButton.svelte";
    import StringModal from "./modals/StringModal.svelte";
    import { getPemFromBase64 } from "./utils";
    import RevocationInfoModal from "./RevocationInfoModal.svelte";
    import MaterializeButton from "./buttons/MaterializeButton.svelte";

    const dispatch = createEventDispatcher();
    export let cert;

    let thumbprint = `${cert.info["Avtrykk (SHA-1)"]}`;

    let modal;
    let pemShown = false;
    let revocationInfoShown = false;

    function onCloseEnd(e) {
        dispatch("close");
    }
    onMount(() => {
        window.M.Modal.init(modal, {
            onCloseEnd: onCloseEnd,
        });

        let thisModal = window.M.Modal.getInstance(modal);
        thisModal.open();
        // Remove the default event listener, since we do not want
        // this modal to close when it has another modal on top.
        document.removeEventListener("keydown", thisModal._handleKeydownBound);
    });

    const handleKeyDown = (e) => {
        if (e.key === "Escape" && !pemShown && !revocationInfoShown) {
            // Only close this modal if the pem modal
            // is not on top of it.
            window.M.Modal.getInstance(modal).close();
        }
    };
    const handleCloseClick = (e) => {
        window.M.Modal.getInstance(modal).close();
    };
</script>

<svelte:window on:keydown={handleKeyDown} />

<div class="modal cert-modal" bind:this={modal}>
    <div class="modal-content">
        <div class="right">
            <a
                href="#!"
                class="modal-action waves-effect waves-green btn-flat"
                on:click={handleCloseClick}
            >
                <i class="material-icons">close</i>
            </a>
        </div>
        <h5>Sertifikat</h5>
        <table class="bordered">
            <thead>
                <tr>
                    <th></th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td> <b>Emne</b></td>
                    <td>{cert.info["Emne"]}</td>
                </tr>
                <tr>
                    <td><b>Utsteder</b></td>
                    <td>{cert.info["Utsteder"]} </td>
                </tr>
                <tr>
                    <td><b>Gyldig fra</b></td>
                    <td>{cert.info["Gyldig fra"]}</td>
                </tr>
                <tr>
                    <td><b>Gyldig til</b></td>
                    <td>{cert.info["Gyldig til"]}</td>
                </tr>
                <tr>
                    <td><b>Serienummer (hex)</b> </td>
                    <td>{cert.info["Serienummer (hex)"]}</td>
                </tr>
                <tr>
                    <td><b>Serienummer (dec)</b></td>
                    <td>{cert.info["Serienummer (int)"]}</td>
                </tr>
                <tr>
                    <td><b>Bruksområde(r)</b></td>
                    <td>{cert.info["Bruksområde(r)"]}</td>
                </tr>
                <tr>
                    <td><b>Nøkkeltype</b></td>
                    <td>{cert.info["Nøkkeltype"]}</td>
                </tr>
                <tr>
                    <td><b>Nøkkelbruk</b></td>
                    <td>{cert.info["Nøkkelbruk"]} </td>
                </tr>
                <tr>
                    <td><b>Utvidet nøkkelbruk</b></td>
                    <td>{cert.info["Utvidet nøkkelbruk"]}</td>
                </tr>
                <tr>
                    <td><b>Status</b></td>
                    <td>{cert.info["Status"]}</td>
                </tr>
                <tr>
                    <td><b>Type</b></td>
                    <td>{cert.info["Type"]}</td>
                </tr>
                <tr>
                    <td><b>Avtrykk (SHA-1)</b></td>
                    <td>{cert.info["Avtrykk (SHA-1)"]}</td>
                </tr>
            </tbody>
        </table>
        <br />
        <div class="modal-footer">
            <MaterializeButton
                data_position="top"
                data_tooltip={cert.revocation_check_unavailable_reason
                    ? `Kan ikke utføre revokeringssjekk fordi ${cert.revocation_check_unavailable_reason}`
                    : "Hent detaljert revokeringsinfo"}
                disabled={cert.revocation_check_unavailable_reason}
                on:click={() => (revocationInfoShown = true)}
            >
                <i class="material-icons">verified_user</i>
            </MaterializeButton>
            <PemButton on:open={() => (pemShown = true)} />
            <DownloadCertButton base64cert={cert.certificate} {thumbprint} />
        </div>
    </div>
</div>

{#if pemShown}
    <StringModal textSelected={true} on:close={() => (pemShown = false)}>
        <p class="pem">{getPemFromBase64(cert.certificate)}</p>
    </StringModal>
{/if}

{#if revocationInfoShown}
    <RevocationInfoModal
        {cert}
        on:close={() => (revocationInfoShown = false)}
    />
{/if}

<style>
    /*
    Materializecss has a modal max height of 70 %
    and that's a bit to small for the certificate display
    so we override it.
    */
    .cert-modal {
        max-height: 94%;
        width: 70%;
        top: 3% !important;
    }
    .pem {
        font:
            10pt Courier New,
            sans-serif;
        padding: 2px 20px;
        white-space: pre-wrap;
    }
</style>
