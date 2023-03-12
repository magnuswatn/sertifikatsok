<script>
    export let base64cert;
    import { createEventDispatcher, onDestroy, onMount } from "svelte";
    import StringModal from "../modals/StringModal.svelte";
    import { getPemFromBase64 } from "../utils";
    import MaterializeButton from "./MaterializeButton.svelte";

    const dispatch = createEventDispatcher();

    let modalOpen = false;

    const handleModalClose = () => {
        modalOpen = false;
        dispatch("close");
    };
    const handleModalOpen = () => {
        modalOpen = true;
        dispatch("open");
    };
</script>

<MaterializeButton
    data_position="top"
    data_tooltip="Vis PEM"
    on:click={handleModalOpen}
>
    <i class="material-icons">content_copy</i>
</MaterializeButton>
{#if modalOpen}
    <StringModal textSelected={true} on:close={handleModalClose}>
        <p class="pem">{getPemFromBase64(base64cert)}</p>
    </StringModal>
{/if}

<style>
    .pem {
        font: 10pt Courier New, sans-serif;
        padding: 2px 20px;
        white-space: pre-wrap;
    }
</style>
