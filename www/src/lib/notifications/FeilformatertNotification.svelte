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
            systemer vil fortsatt kunne tolke og bruke de korrekt, mens andre
            systemer vil avvise sertifikatene. Slike sertifikater bør erstattes,
            og de vises derfor som ugyldige.
        </p>
    </StringModal>
{/if}
