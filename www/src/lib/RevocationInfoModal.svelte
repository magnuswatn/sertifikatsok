<script>
    import { createEventDispatcher, onMount } from "svelte";
    import { callRevocationInfoApi } from "./utils";
    import ErrorPage from "./ErrorPage.svelte";
    import ErrorMessage from "./messages/ErrorMessage.svelte";
    import Spinner from "./Spinner.svelte";
    const dispatch = createEventDispatcher();
    export let cert;

    let modal;

    onMount(() => {
        window.M.Modal.init(modal, {
            onCloseEnd: () => dispatch("close"),
        }).open();
    });

    const handleCloseClick = (e) => {
        // We need to do this ourselves, so that
        // we don't drag the CertModal down with
        // us when this is on top of that.
        window.M.Modal.getInstance(modal).close();
    };
</script>

<div class="modal ocsp-modal" bind:this={modal}>
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

        {#await callRevocationInfoApi(window.location.search, cert.certificate)}
            <Spinner />
        {:then response}
            <h6>OCSP-info</h6>

            {#if !response.ocsp_result}
                <p>Sertifikatet inneholder ikke OCSP-informasjon</p>
            {:else if response.ocsp_result.error}
                <ErrorMessage message={response.ocsp_result.error} />
            {:else}
                <table class="bordered">
                    <thead>
                        <tr>
                            <th></th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td> <b>Status ved OCSP-sjekk</b></td>
                            <td>{response.ocsp_result.status}</td>
                        </tr>
                        {#if response.ocsp_result.revoked_at}
                            <tr>
                                <td> <b>Revokeringstidspunkt</b></td>
                                <td>{response.ocsp_result.revoked_at}</td>
                            </tr>
                        {/if}
                        {#if response.ocsp_result.reason}
                            <tr>
                                <td> <b>Revokeringsårsak</b></td>
                                <td>{response.ocsp_result.reason}</td>
                            </tr>
                        {/if}
                        <tr>
                            <td><b>OCSP-respons produsert</b></td>
                            <td>{response.ocsp_result.produced_at} </td>
                        </tr>
                        <tr>
                            <td><b>OCSP-respons gyldig fra</b></td>
                            <td>{response.ocsp_result.this_update} </td>
                        </tr>
                        {#if response.ocsp_result.next_update}
                            <tr>
                                <td><b>OCSP-respons gyldig til</b></td>
                                <td>{response.ocsp_result.next_update}</td>
                            </tr>
                        {/if}
                    </tbody>
                </table>
            {/if}

            <br />
            <h6>CRL-info</h6>
            {#if !response.crl_result}
                <p>Sertifikatet inneholder ikke CRL-informasjon</p>
            {:else if response.crl_result.error}
                <ErrorMessage message={response.crl_result.error} />
            {:else}
                <table class="bordered">
                    <thead>
                        <tr>
                            <th></th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td> <b>Revokeringstidspunkt</b></td>
                            <td
                                >{response.crl_result.revoked_at ||
                                    "Ingen (sertifikatet er ikke i CRL)"}</td
                            >
                        </tr>
                        {#if response.crl_result.reason}
                            <tr>
                                <td> <b>Revokeringsårsak</b></td>
                                <td>{response.crl_result.reason}</td>
                            </tr>
                        {/if}
                        {#if response.crl_result.crl_number}
                            <tr>
                                <td> <b>CRL-nummer</b></td>
                                <td>{response.crl_result.crl_number}</td>
                            </tr>
                        {/if}
                        <tr>
                            <td><b>CRL gyldig fra</b></td>
                            <td>{response.crl_result.this_update} </td>
                        </tr>
                        <tr>
                            <td><b>CRL gyldig til</b></td>
                            <td>{response.crl_result.next_update} </td>
                        </tr>
                    </tbody>
                </table>
            {/if}
            <br />
        {:catch error}
            <ErrorPage {error} />
        {/await}
    </div>
</div>

<style>
    table {
        table-layout: fixed;
        width: 100%;
    }
</style>
