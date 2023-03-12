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
        <h4>Norske kvalifiserte sertifikater</h4>
        <p>
            Norske kvalifiserte sertifikater er digitale ID-papirer, som kan
            brukes til å bekrefte identitet i den digitale verdenen. De baserer
            seg på samme teknologi som f.eks. SSL-sertifikater, og er
            spesifisert i <a
                href="https://www.regjeringen.no/no/dokumenter/kravspesifikasjon-for-pki-i-offentlig-se/id611085/"
                >Kravspesifikasjon for PKI i offentlig sektor</a
            >.
            <br />
        </p>
        <p>Det finnes i praksis to typer norske kvalifiserte sertifikater:</p>
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
        Virksomhetssertifikater identifiserer en virksomhet registrert i Brønnøysundregistrene.
        Brukes typisk til:
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
            Det er i praksis to utstedere av kvalifiserte sertifikater Norge i
            dag, <a href="https://www.buypass.no">Buypass</a>
            og <a href="https://www.commfides.com/">Commfides</a>.
        </p>
    </StringModal>
{/if}
