<script>
    export let cert;
    import { onMount } from "svelte";
    import CertModal from "./CertModal.svelte";
    let cert_open = false;

    function handleClick(event) {
        cert_open = true;
        let thumbprint = `${cert.info["Avtrykk (SHA-1)"]}`;
        history.replaceState(null, "", `#${thumbprint}`);
    }
    function handleModalClose(event) {
        cert_open = false;
        history.replaceState(null, "", "#!");
    }

    function openIfHashMatch() {
        let thumbprint = `${cert.info["Avtrykk (SHA-1)"]}`;
        if (window.location.hash.toLowerCase() === `#${thumbprint}`) {
            cert_open = true;
        }
    }

    onMount(openIfHashMatch);
</script>

<svelte:window on:hashchange={openIfHashMatch} />

<a href="#!" on:click|preventDefault={handleClick}>
    <div class="col s12 m6">
        <div class="card blue-grey darken-1 hoverable cert">
            <div class="card-content white-text">
                <span class="card-title">{cert.name}</span>
                <p />
                <div class="left">Bruksområde(r)</div>
                <div class="right">{cert.info["Bruksområde(r)"]}</div>
                <br />
                <div class="left">Serienummer (hex)</div>
                <div class="right">{cert.info["Serienummer (hex)"]}</div>
                <br />
                <div class="left">Serienummer (int)</div>
                <div class="right">{cert.info["Serienummer (int)"]}</div>
                <br />
                <div class="left">Avtrykk (SHA-1)</div>
                <div class="right">{cert.info["Avtrykk (SHA-1)"]}</div>
                <br />
            </div>
        </div>
    </div>
</a>
{#if cert_open}
    <CertModal {cert} on:close={handleModalClose} />
{/if}
