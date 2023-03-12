<script>
    import StringModal from "../modals/StringModal.svelte";
    import NotificationMessage from "./NotificationMessage.svelte";

    let modalOpen = false;
</script>

<NotificationMessage on:click={() => (modalOpen = true)}>
    Disse sertifikatene er av en ukjent type. Trykk her for å lese mer.
</NotificationMessage>

{#if modalOpen}
    <StringModal on:close={() => (modalOpen = false)}>
        <h4>Ukjent sertifikattype</h4>
        <p>
            Alle norske kvalifiserte sertifikater skal ha en en kode i seg
            (Policy OID) som beskriver hvilken type sertifikat det er. Disse
            sertifikatene hadde en ukjent kode i seg, som tyder på at det ikke
            er et vanlig sertifikat. Bør kun stoles på eller brukes i spesielle
            tilfeller.
        </p>
    </StringModal>
{/if}
