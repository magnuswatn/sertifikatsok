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
            Disse sertifikatene er utstedt til en underenhet av denne
            organisasjonen. Slike sertifikater har organisasjonsnummeret til
            hovedenheten i serialNumber- (SEID 1) eller
            organizationIdentifier-feltet (SEID 2) og organisasjonsnummeret til
            underenheten i OU-feltet.<br /><br />Eksempel:
        </p>
        <div class="row">
            <div class="col s12 m5">
                <div class="card-panel teal">
                    <span class="white-text">
                        serialNumber = 995546973<br />
                        O = WATN IT SYSTEM
                        <br />OU = WATN UNDERENHET-113328475
                    </span>
                </div>
            </div>
        </div>
        Vær obs på at slike sertifikater kan bli tolket forskjellig fra system til
        system. Noen vil tolke det som at det tilhører underenheten, mens andre vil
        tolke det som tilhørende hovedenheten.
    </StringModal>
{/if}
