<script>
    import StringModal from "../modals/StringModal.svelte";
    import MaterializeButton from "./MaterializeButton.svelte";

    let modalOpen = false;
</script>

<div class="fixed-action-btn">
    <MaterializeButton
        data_position="left"
        data_tooltip="Litt forklaring"
        on:click={() => (modalOpen = true)}
    >
        <div class="center"><b>?</b></div>
    </MaterializeButton>
</div>
{#if modalOpen}
    <StringModal on:close={() => (modalOpen = false)}>
        <h4>Norske person- og virksomhetssertifikater</h4>
        <p>
            Norske person- og virksomhetssertifikater er digitale ID-papirer,
            som kan brukes til å bekrefte identitet i den digitale verdenen. De
            baserer seg på samme teknologi som f.eks. SSL-sertifikater, og er
            spesifisert av <a
                href="https://www.nkom.no/internett/elektronisk-id-og-tillitstjenester/seid-prosjektet"
                target="_blank"
                rel="noreferrer">SEID-samarbeidet</a
            >.
            <br />
        </p>
        <h5>Person-sertifikater</h5>
        Person-sertifikater representerer en norsk statsborger i folkeregisteret.
        Slike sertifikater brukes typisk til:
        <ul class="browser-default">
            <li>Innlogging på tjenester som krever høy sikkerhet.</li>
            <li>Signering av f.eks. avtaler eller e-resepter</li>
            <li>Signering og kryptering av e-poster (S/MIME)</li>
        </ul>
        Person-sertifikater utstedes kun i fysisk form, da enten et smartkort ("tippekort")
        eller en USB-pinne.
        <br /><br />
        <h5>Virksomhetssertifikater</h5>
        Virksomhetssertifikater identifiserer en virksomhet registrert i Enhetsregisteret
        (Brønnøysundregistrene). Brukes typisk til:
        <ul class="browser-default">
            <li>
                Autentisering av virksomheten i maskin-til-maskin-kommunikasjon
                (f.eks. mellom fagsystemer i helsesektoren)
            </li>
            <li>Signering av dokumenter på vegne av virksomheten</li>
        </ul>
        Virksomhetssertifikater er typisk "soft-sertifikater", men de finnes også
        i fysisk variant, da i form av smartkort.
        <br /><br />
        <p>
            Det er i praksis to utstedere av person- og virksomhetssertifikater
            i Norge i dag, <a href="https://www.buypass.no">Buypass</a>
            og <a href="https://www.commfides.com/">Commfides</a>.
        </p>
    </StringModal>
{/if}
