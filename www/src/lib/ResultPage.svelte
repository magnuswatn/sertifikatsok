<script>
    export let response;

    import SearchDetailsButton from "./buttons/SearchDetailsButton.svelte";
    import CertCollapsible from "./CertCollapsible.svelte";
    import ErrorMessage from "./messages/ErrorMessage.svelte";
    import UnderenhetMessage from "./messages/UnderenhetMessage.svelte";

    document.title = `Sertifikatsøk - ${response.subject}`;
</script>

{#each response.errors as error}
    <ErrorMessage message={error} />
{/each}

{#if response.searchDetails.hovedOrgNr}
    <UnderenhetMessage orgnr={response.searchDetails.hovedOrgNr} />
{/if}

<h5 class="center-align">
    Fant {response.certificate_sets.length} sett med {response.searchDetails.Type.toLowerCase()}
    for {response.subject}
</h5>
<div class="center-align">
    <SearchDetailsButton search_details={response.searchDetails} />
</div>

{#each response.certificate_sets as cert_set}
    <CertCollapsible {cert_set} />
{/each}
