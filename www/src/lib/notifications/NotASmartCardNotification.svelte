<script>
    import StringModal from "../modals/StringModal.svelte";
    import NotificationMessage from "./NotificationMessage.svelte";

    let modalOpen = false;
</script>

<NotificationMessage on:click={() => (modalOpen = true)}>
    Vær obs på at disse sertifikatene ikke tilhører et smartkort
</NotificationMessage>

{#if modalOpen}
    <StringModal on:close={() => (modalOpen = false)}>
        <h4>Ikke smartkort</h4>
        <p>
            Disse sertifikatene stammer ikke fra et vanlig smartkort
            ("tippekort"). De stammer typisk fra et Buypass ID i
            mobil-abonnement.
        </p>
    </StringModal>
{/if}
