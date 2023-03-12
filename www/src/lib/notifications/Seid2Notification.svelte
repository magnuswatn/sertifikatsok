<script>
    import StringModal from "../modals/StringModal.svelte";
    import NotificationMessage from "./NotificationMessage.svelte";

    let modalOpen = false;
</script>

<NotificationMessage on:click={() => (modalOpen = true)}>
    Disse sertifikatene er utstedt ihht. de nye SEID v2.0-profilene. Trykk her
    for å lese mer.
</NotificationMessage>

{#if modalOpen}
    <StringModal on:close={() => (modalOpen = false)}>
        <h4>SEID v2.0-sertifikat</h4>
        <p>
            Disse sertifikatene er uststedt ihht. de nye sertifikatprofilene,
            som omtales som SEID v2.0. Dette gjør at f.eks. organisasjonsnummer
            er angitt på en annen måte, og kan medføre at sertifikatet ikke vil
            bli tolket korrekt av eldre systemer.
        </p>
    </StringModal>
{/if}
