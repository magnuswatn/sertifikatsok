<script>
    import StringModal from "../modals/StringModal.svelte";
    import NotificationMessage from "./NotificationMessage.svelte";

    let modalOpen = false;
</script>

<NotificationMessage warning={true} on:click={() => (modalOpen = true)}>
    Disse sertifikatene er feilformaterte og det er derfor ikke mulig å vise all
    informasjon som normalt
</NotificationMessage>

{#if modalOpen}
    <StringModal on:close={() => (modalOpen = false)}>
        <h4>Feilformaterte sertifikater</h4>
        <p>
            Disse sertifikatene er produsert feil av sertifikatutstederen (dette
            kan f.eks. være at særnorske tegn er kodet på feil måte). Noen
            systemer vil fortsatt kunne tolke og bruke det korrekt, mens andre
            systemer vil avvise sertifikatet. Dette sertifikatet bør erstattes,
            og vises derfor som ugyldig.
        </p>
    </StringModal>
{/if}
