<script>
    export let ldap_url;

    import StringModal from "../modals/StringModal.svelte";
    import MaterializeButton from "./MaterializeButton.svelte";

    let modalOpen = false;
</script>

<MaterializeButton
    on:click={() => (modalOpen = true)}
    data_position="top"
    data_tooltip="Se LDAP-streng for dette settet"
>
    <i class="material-icons">link</i>
</MaterializeButton>

{#if modalOpen}
    <StringModal textSelected={true} on:close={() => (modalOpen = false)}>
        {ldap_url}
    </StringModal>
{/if}
