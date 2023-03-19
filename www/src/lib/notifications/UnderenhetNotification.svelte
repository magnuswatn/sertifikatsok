<script>
    import StringModal from "../modals/StringModal.svelte";
    import NotificationMessage from "./NotificationMessage.svelte";

    let modalOpen = false;
</script>

<NotificationMessage on:click={() => (modalOpen = true)}>
    Disse sertifikatene er utstedt til en underenhet. Trykk her for å lese mer.
</NotificationMessage>

{#if modalOpen}
    <StringModal on:close={() => (modalOpen = false)}>
        <h4>Sertifikater utstedt til underenhet</h4>
        <p>
            Disse sertifikatene er utstedt til en underenhet. Slike sertifikater
            har organisasjonsnummeret til hovedenheten spesifisert på vanlig
            måte (serialNumber- (SEID 1) eller organizationIdentifier-feltet
            (SEID 2)) og organisasjonsnummeret til underenheten i OU-feltet.
            <br />
            <br />
            Eksempel:
        </p>

        <div class="card-parent">
            <div class="card-panel teal">
                <span class="white-text">
                    organizationIdentifier = NTRNO-987654321<br />
                    O = HOVEDENHET AS<br />
                    OU = ER:NO-123456789-UNDERENHET AS
                </span>
            </div>
        </div>
        Vær obs på at slike sertifikater kan bli tolket forskjellig fra system til
        system. Noen vil tolke det som at det tilhører underenheten, mens andre vil
        tolke det som tilhørende hovedenheten.
    </StringModal>
{/if}

<style>
    .card-parent {
        display: flex;
    }
</style>
