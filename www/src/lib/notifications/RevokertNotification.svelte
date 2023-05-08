<script>
    import StringModal from "../modals/StringModal.svelte";
    import NotificationMessage from "./NotificationMessage.svelte";

    let modalOpen = false;
</script>

<NotificationMessage warning={true} on:click={() => (modalOpen = true)}>
    Disse sertifikatene er revokerte og dermed ikke gyldige
</NotificationMessage>

{#if modalOpen}
    <StringModal on:close={() => (modalOpen = false)}>
        <h4>Revokerte sertifikater</h4>
        <p>
            Revokerte sertifikater er tilbaketrukket fra sertifikatutstederen.
            Det kan være pga. informasjonen i sertifikatet ikke lenger er gyldig
            (f.eks. virksomhet avviklet), eller at den private nøkkelen har
            kommet på avveie. Slike sertifikater må ikke stoles på eller brukes.
        </p>
    </StringModal>
{/if}
